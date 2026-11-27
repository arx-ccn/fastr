package ws

import "core:fmt"
import "core:mem"
import "core:net"
import "core:sync"
import "core:sync/chan"
import "core:sys/linux"
import "core:thread"
import "core:time"

import "../tls"

@(private = "file")
Plain_Server :: struct {
	listener:                net.TCP_Socket,
	relay:                   ^Relay,
	active, max_connections: int,
	next_id:                 u64,
	workers:                 [4]^Plain_Worker,
	worker_count:            int,
	user:                    rawptr,
	upgrade:                 proc(user: rawptr, req: ^Request) -> string,
	http:                    proc(
		user: rawptr,
		stream: ^tls.Server_Stream,
		req: ^Request,
		extra: []u8,
	),
}

@(private = "file")
Plain_Worker :: struct {
	server:        ^Plain_Server,
	poll:          linux.Fd,
	accept_paused: Maybe(time.Tick),
	head, tail:    ^Plain_Client,
}

@(private)
Plain_Client :: struct {
	worker:   ^Plain_Worker,
	next:     ^Plain_Client,
	refs:     int, // reader (or HTTP owner) and, if started, the lazy writer
	stream:   tls.Server_Stream,
	state:    Conn_State,
	outbox:   Outbox,
	id:       u64,
	upgraded: bool,
}

// Plaintext readers share one listener. The HTTP fallback handles a borrowed
// request on a blocking worker; it does not own the socket or the request.
serve_plaintext :: proc(
	relay: ^Relay,
	listener: net.TCP_Socket,
	max_connections: int,
	user: rawptr,
	upgrade: proc(user: rawptr, req: ^Request) -> string,
	http: proc(user: rawptr, stream: ^tls.Server_Stream, req: ^Request, extra: []u8),
) -> bool {
	server := Plain_Server {
		listener        = listener,
		relay           = relay,
		max_connections = max_connections,
		user            = user,
		upgrade         = upgrade,
		http            = http,
	}
	if net.set_blocking(listener, false) != nil {
		return false
	}
	workers: [4]Plain_Worker
	for &worker, i in workers {
		flags: linux.EPoll_Flags = {.FDCLOEXEC}
		fd := linux.syscall(linux.SYS_epoll_create1, transmute(i32)flags)
		if fd < 0 {
			for old in workers[:i] {linux.close(old.poll)}
			return false
		}
		worker = {
			server = &server,
			poll   = linux.Fd(fd),
		}
		if plain_watch_listener(&worker) != .NONE {
			for old in workers[:i + 1] {linux.close(old.poll)}
			return false
		}
	}
	server.workers[0] = &workers[0]
	server.worker_count = 1
	threads: [len(workers) - 1]^thread.Thread
	for &worker in workers[1:] {
		t := thread.create(proc(t: ^thread.Thread) {plain_loop((^Plain_Worker)(t.data))})
		if t == nil {
			fmt.eprintln("fastr: cannot start another plaintext reader")
			linux.close(worker.poll)
			continue
		}
		t.data = &worker
		threads[server.worker_count - 1] = t
		server.workers[server.worker_count] = &worker
		server.worker_count += 1
	}
	for t in threads[:server.worker_count - 1] {
		thread.start(t)
	}
	plain_loop(&workers[0])
	unreachable()
}

@(private = "file")
plain_watch_listener :: proc(w: ^Plain_Worker) -> linux.Errno {
	event := linux.EPoll_Event {
		events = {.IN, .EXCLUSIVE},
	}
	return linux.epoll_ctl(w.poll, .ADD, linux.Fd(w.server.listener), &event)
}

@(private = "file")
plain_loop :: proc(w: ^Plain_Worker) {
	events: [64]linux.EPoll_Event = ---
	for {
		timeout := i32(-1)
		if paused, parked := w.accept_paused.?; parked {
			left := 100 * time.Millisecond - time.tick_diff(paused, time.tick_now())
			if left > 0 {
				timeout = i32((left + time.Millisecond - 1) / time.Millisecond)
			} else {
				if err := plain_watch_listener(w); err != .NONE {
					panic(fmt.tprintf("fastr: epoll listener: %v", err))
				}
				w.accept_paused = nil
			}
		}
		last := w.tail
		if last != nil {
			timeout = 0
		}
		n, err := linux.epoll_pwait(w.poll, raw_data(events[:]), len(events), timeout, nil)
		if err == .EINTR {
			continue
		}
		if err != .NONE {
			panic(fmt.tprintf("fastr: epoll wait: %v", err))
		}
		for &event in events[:n] {
			if event.data.ptr == nil {
				plain_accept(w)
			} else {
				c := (^Plain_Client)(event.data.ptr)
				if c.next == nil {
					plain_service(c)
					free_all(context.temp_allocator)
				}
			}
		}
		if last == nil {
			continue
		}
		for _ in 0 ..< len(events) {
			c := w.head
			done := c == last
			if c == w.tail {
				w.head, w.tail = nil, nil
			} else {
				w.head = c.next
			}
			c.next = nil
			plain_frames(c)
			if done {
				break
			}
		}
	}
}

@(private = "file")
plain_accept :: proc(w: ^Plain_Worker) {
	s := w.server
	for _ in 0 ..< 32 {
		addr: linux.Sock_Addr_Any = ---
		fd, err := linux.accept(linux.Fd(s.listener), &addr, {.CLOEXEC})
		if err == .EINTR || err == .ECONNABORTED {
			continue
		}
		if err == .EAGAIN {
			return
		}
		if err != .NONE {
			fmt.eprintfln("accept failed: %v; backing off", err)
			if drop := linux.epoll_ctl(w.poll, .DEL, linux.Fd(s.listener), nil); drop != .NONE {
				panic(fmt.tprintf("fastr: epoll listener removal: %v", drop))
			}
			w.accept_paused = time.tick_now()
			return
		}
		active := sync.atomic_load(&s.active)
		for active < s.max_connections {
			previous, won := sync.atomic_compare_exchange_weak(&s.active, active, active + 1)
			if won {break}
			active = previous
		}
		if active >= s.max_connections {
			linux.close(fd)
			continue
		}
		client := new(Plain_Client)
		client.stream.sock = net.TCP_Socket(fd)
		client.id = sync.atomic_add(&s.next_id, 1) + 1
		client.refs = 1
		// The worker woken for the listener may accept a whole burst.
		// Distribute its clients without a userspace handoff queue.
		client.worker = s.workers[(client.id - 1) % u64(s.worker_count)]
		_ = net.set_option(client.stream.sock, .TCP_Nodelay, true)
		event := linux.EPoll_Event {
			events = {.IN, .RDHUP},
			data = {ptr = client},
		}
		if linux.epoll_ctl(client.worker.poll, .ADD, fd, &event) != .NONE {
			plain_release(client)
		}
	}
}

@(private = "file")
Plain_Http :: struct {
	client: ^Plain_Client,
	req:    Request,
	extra:  []u8,
}

@(private = "file")
plain_http :: proc(job: ^Plain_Http) {
	defer free(job)
	client := job.client
	defer plain_release(client)
	defer free_all(context.temp_allocator)
	s := client.worker.server
	s.http(s.user, &client.stream, &job.req, job.extra)
}

@(private = "file")
plain_service :: proc(c: ^Plain_Client) {
	conn := &c.state.conn
	fd := linux.Fd(c.stream.sock)
	if c.upgraded {
		n, err := linux.recv(fd, conn_read_buf(conn), {.DONTWAIT})
		if err == .EAGAIN || err == .EINTR {
			return
		}
		if err != .NONE || n == 0 {
			plain_end(c, 0)
			return
		}
		conn.rend += n
		plain_frames(c)
		return
	}

	// Use the future WebSocket receive buffer until the HTTP head is complete.
	n, err := linux.recv(fd, conn.rbuf[conn.rend:MAX_HEADER_BYTES], {.DONTWAIT})
	if err == .EAGAIN || err == .EINTR {
		return
	}
	if err != .NONE || n == 0 {
		plain_end(c, 0)
		return
	}
	conn.rend += n
	req: Request = ---
	consumed, req_err := parse_request(conn.rbuf[:conn.rend], &req)
	if req_err == .Incomplete {
		return
	}
	if req_err != .None {
		plain_end(c, 0)
		return
	}

	s := c.worker.server
	extra := conn.rbuf[consumed:conn.rend]
	key := s.upgrade(s.user, &req)
	if key == "" {
		plain_unregister(c)
		job := new(Plain_Http)
		job^ = {
			client = c,
			req    = req,
			extra  = extra,
		}
		if thread.create_and_start_with_poly_data(job, plain_http, self_cleanup = true) == nil {
			free(job)
			plain_release(c)
		}
		return
	}

	// The key also borrows rbuf. Finish the HTTP response before moving the
	// preloaded frame bytes over the head. Do not block on the initial write.
	wire := make([dynamic]u8, HANDSHAKE_RESPONSE_LEN, HANDSHAKE_RESPONSE_LEN + 64)
	write_handshake_response(wire[:], key)
	c.outbox.plain_owner = c
	conn_state_init(&c.state, &c.outbox, s.relay, &c.stream, c.id, extra)
	c.upgraded = true
	if !outbox_send(&c.outbox, Out_Batch{wire = wire}, &c.state.replay_spare) {
		delete(wire)
		plain_end(c, 0)
		return
	}
	begin_auth(&c.state)
	plain_frames(c)
}

@(private = "file")
plain_frames :: proc(c: ^Plain_Client) {
	cs := &c.state
	old_temp := context.temp_allocator
	defer context.temp_allocator = old_temp
	context.temp_allocator = mem.dynamic_arena_allocator(&cs.scratch)
	for _ in 0 ..< 8 {
		incoming, err := conn_parse(&cs.conn)
		if err != .None || incoming.event == .Close {
			terminal := incoming.close_code if err == .None else close_code_for_error(err)
			plain_end(c, terminal)
			return
		}
		if incoming.event == .None {
			return
		}
		consume_incoming(cs, incoming)
	}
	if cs.conn.rstart < cs.conn.rend {
		// epoll only sees unread kernel bytes. Queue buffered frames ourselves;
		// a self-link marks the tail as queued without a separate flag.
		w := c.worker
		c.next = c
		if w.tail == nil {
			w.head = c
		} else {
			w.tail.next = c
		}
		w.tail = c
	}
}

@(private = "file")
plain_unregister :: proc(c: ^Plain_Client) {
	err := linux.epoll_ctl(c.worker.poll, .DEL, linux.Fd(c.stream.sock), nil)
	if err != .NONE {
		panic(fmt.tprintf("fastr: epoll client removal: %v", err))
	}
}

@(private = "file")
plain_end :: proc(c: ^Plain_Client, terminal: u16) {
	plain_unregister(c)
	if c.upgraded {
		detach_outbox(&c.state, terminal)
		// Keep the reactor's reference until close has finished waking receivers.
		chan.close(c.outbox.ch)
	}
	plain_release(c)
}

@(private)
plain_release :: proc(c: ^Plain_Client) {
	if sync.atomic_sub(&c.refs, 1) != 1 {
		return
	}
	if c.upgraded {
		conn_state_destroy(&c.state)
	}
	net.close(c.stream.sock)
	sync.atomic_sub(&c.worker.server.active, 1)
	free(c)
}
