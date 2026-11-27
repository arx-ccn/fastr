package tls

import cc "core:c"
import "core:net"
import "core:strings"
import "core:sys/linux"
import "core:time"

BIO :: struct {}

// The caller owns sock; the connection thread owns ssl and bio.
Server_Stream :: struct {
	sock:        net.TCP_Socket,
	ssl:         ^SSL,
	bio:         ^BIO,
	failed:      bool,
	tcp_eof:     bool,
	read_start:  time.Tick,
	read_limit:  time.Duration,
	close_start: Maybe(time.Tick),
}

stream_recv :: proc(s: ^Server_Stream, buf: []u8) -> (n: int, err: Error) {
	if len(buf) == 0 {
		return 0, .None
	}
	when ENABLED {
		if s.ssl != nil {
			return recv_tls(s, buf)
		}
	}
	got, recv_err := net.recv_tcp(s.sock, buf)
	if recv_err != nil {
		return got, .Io
	}
	return got, .None
}

stream_send :: proc(s: ^Server_Stream, buf: []u8) -> Error {
	if len(buf) == 0 {
		return .None
	}
	when ENABLED {
		if s.ssl != nil {
			return send_tls(s, buf)
		}
	}
	n, err := net.send_tcp(s.sock, buf)
	if err != nil || n != len(buf) {
		return .Io
	}
	return .None
}

when ENABLED {
	foreign import libssl "system:ssl"
	foreign import libcrypto "system:crypto"

	@(default_calling_convention = "c")
	foreign libssl {
		TLS_server_method :: proc() -> ^SSL_METHOD ---
		SSL_CTX_ctrl :: proc(ctx: ^SSL_CTX, cmd: cc.int, larg: cc.long, parg: rawptr) -> cc.long ---
		SSL_CTX_set_options :: proc(ctx: ^SSL_CTX, options: u64) -> u64 ---
		SSL_CTX_set_default_passwd_cb :: proc(ctx: ^SSL_CTX, cb: Password_Callback) ---
		SSL_CTX_use_certificate_chain_file :: proc(ctx: ^SSL_CTX, file: cstring) -> cc.int ---
		SSL_CTX_use_PrivateKey_file :: proc(ctx: ^SSL_CTX, file: cstring, typ: cc.int) -> cc.int ---
		SSL_CTX_check_private_key :: proc(ctx: ^SSL_CTX) -> cc.int ---
		SSL_set_bio :: proc(ssl: ^SSL, rbio, wbio: ^BIO) ---
		SSL_accept :: proc(ssl: ^SSL) -> cc.int ---
		SSL_get_error :: proc(ssl: ^SSL, result: cc.int) -> cc.int ---
	}

	@(default_calling_convention = "c")
	foreign libcrypto {
		ERR_clear_error :: proc() ---
		ERR_peek_last_error :: proc() -> cc.ulong ---
		BIO_new_bio_pair :: proc(a: ^^BIO, a_size: cc.size_t, b: ^^BIO, b_size: cc.size_t) -> cc.int ---
		BIO_free :: proc(b: ^BIO) -> cc.int ---
		BIO_ctrl :: proc(b: ^BIO, cmd: cc.int, larg: cc.long, parg: rawptr) -> cc.long ---
		BIO_ctrl_pending :: proc(b: ^BIO) -> cc.size_t ---
		BIO_ctrl_get_write_guarantee :: proc(b: ^BIO) -> cc.size_t ---
		BIO_nwrite0 :: proc(b: ^BIO, buf: ^[^]u8) -> cc.int ---
		BIO_nwrite :: proc(b: ^BIO, buf: ^[^]u8, n: cc.int) -> cc.int ---
		BIO_nread0 :: proc(b: ^BIO, buf: ^[^]u8) -> cc.int ---
		BIO_nread :: proc(b: ^BIO, buf: ^[^]u8, n: cc.int) -> cc.int ---
	}

	@(private = "file")
	Password_Callback :: #type proc "c" (buf: [^]u8, size, rwflag: cc.int, user: rawptr) -> cc.int

	@(private = "file")
	no_password :: proc "c" (buf: [^]u8, size, rwflag: cc.int, user: rawptr) -> cc.int {
		return 0
	}

	@(private = "file")
	SSL_CTRL_SET_MIN_PROTO_VERSION :: 123
	@(private = "file")
	TLS1_2_VERSION :: 0x0303
	@(private = "file")
	SSL_OP_NO_RENEGOTIATION :: u64(1) << 30
	@(private = "file")
	SSL_FILETYPE_PEM :: 1
	@(private = "file")
	BIO_C_SHUTDOWN_WR :: 142
	@(private = "file")
	RING_SIZE :: 64 * 1024
	@(private = "file")
	CONTROL_RESERVE :: 32 * 1024
	SERVER_RECORD_MAX :: 16 * 1024
	SERVER_HEAD_LIMIT :: 10 * time.Second
	SERVER_IO_LIMIT :: 30 * time.Second
	SERVER_CLOSE_LIMIT :: 2 * time.Second

	Step :: enum {
		Progress,
		Want_Read,
		Want_Write,
		Closed,
		Failed,
	}

	server_ctx :: proc(cert, key: string) -> (ctx: ^SSL_CTX, err: Error) {
		ctx = SSL_CTX_new(TLS_server_method())
		if ctx == nil {
			return nil, .Init
		}
		err = configure_ctx(ctx, cert, key)
		if err != .None {
			SSL_CTX_free(ctx)
			return nil, err
		}
		return ctx, .None
	}

	@(private = "file")
	configure_ctx :: proc(ctx: ^SSL_CTX, cert, key: string) -> Error {
		if SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, nil) != 1 {
			return .Init
		}
		SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION)
		SSL_CTX_set_default_passwd_cb(ctx, no_password)
		if SSL_CTX_use_certificate_chain_file(
			   ctx,
			   strings.clone_to_cstring(cert, context.temp_allocator),
		   ) !=
		   1 {
			return .Certificate
		}
		ERR_clear_error()
		if SSL_CTX_use_PrivateKey_file(
			   ctx,
			   strings.clone_to_cstring(key, context.temp_allocator),
			   SSL_FILETYPE_PEM,
		   ) !=
		   1 {
			X509_KEY_VALUES_MISMATCH :: (11 << 23) | 116
			if ERR_peek_last_error() == X509_KEY_VALUES_MISMATCH {
				return .Key_Mismatch
			}
			return .Private_Key
		}
		if SSL_CTX_check_private_key(ctx) != 1 {
			return .Key_Mismatch
		}
		return .None
	}

	server_attach :: proc(s: ^Server_Stream, ssl: ^SSL) -> Error {
		s.ssl = ssl
		internal: ^BIO
		if BIO_new_bio_pair(&internal, RING_SIZE, &s.bio, RING_SIZE) != 1 {
			s.failed = true
			return .Init
		}
		SSL_set_bio(ssl, internal, internal)
		return .None
	}

	server_handshake :: proc(s: ^Server_Stream) -> Error {
		budget := Budget{time.tick_now(), 10 * time.Second}
		for {
			ERR_clear_error()
			r := SSL_accept(s.ssl)
			if r == 1 {
				return wait_step(s, .Progress, &budget)
			}
			step := ssl_step(s, r)
			if step == .Failed || step == .Closed {
				// SSL_accept may have queued a fatal alert. Flush without more SSL I/O.
				s.failed = true
				_ = wait_step(s, .Progress, &budget)
				return .Handshake
			}
			wait_step(s, step, &budget) or_return
		}
	}

	server_read :: proc(s: ^Server_Stream, buf: []u8) -> (n: int, step: Step) {
		ERR_clear_error()
		r := SSL_read(s.ssl, raw_data(buf), cc.int(min(len(buf), int(max(cc.int)))))
		if r > 0 {
			return int(r), .Progress
		}
		return 0, ssl_step(s, r)
	}

	server_write :: proc(s: ^Server_Stream, buf: []u8) -> (n: int, step: Step) {
		ERR_clear_error()
		r := SSL_write(s.ssl, raw_data(buf), cc.int(len(buf)))
		if r > 0 {
			return int(r), .Progress
		}
		return 0, ssl_step(s, r)
	}

	@(private = "file")
	ssl_step :: proc(s: ^Server_Stream, result: cc.int) -> Step {
		SSL_ERROR_WANT_READ :: 2
		SSL_ERROR_WANT_WRITE :: 3
		SSL_ERROR_ZERO_RETURN :: 6
		switch SSL_get_error(s.ssl, result) {
		case SSL_ERROR_WANT_READ:
			return .Want_Read
		case SSL_ERROR_WANT_WRITE:
			return .Want_Write
		case SSL_ERROR_ZERO_RETURN:
			return .Closed
		}
		s.failed = true
		return .Failed
	}

	server_pending :: proc(s: ^Server_Stream) -> int {
		return int(BIO_ctrl_pending(s.bio))
	}

	// Leave room for protocol writes while application output is blocked.
	server_can_write :: proc(s: ^Server_Stream) -> bool {
		return RING_SIZE - server_pending(s) >= CONTROL_RESERVE + SERVER_RECORD_MAX
	}

	server_fill :: proc(s: ^Server_Stream) -> bool {
		if s.tcp_eof {
			return false
		}
		p: [^]u8
		space := BIO_nwrite0(s.bio, &p)
		if space <= 0 {
			return false
		}
		for {
			n, err := linux.recv(linux.Fd(s.sock), p[:space], {.DONTWAIT})
			#partial switch err {
			case .NONE:
				if n == 0 {
					s.tcp_eof = true
					s.failed = BIO_ctrl(s.bio, BIO_C_SHUTDOWN_WR, 0, nil) != 1
				} else {
					s.failed = BIO_nwrite(s.bio, &p, cc.int(n)) != cc.int(n)
				}
				return !s.failed
			case .EINTR:
				continue
			case .EAGAIN:
				return false
			case:
				s.failed = true
				return false
			}
		}
	}

	server_flush :: proc(s: ^Server_Stream) -> int {
		p: [^]u8
		pending := BIO_nread0(s.bio, &p)
		if pending <= 0 {
			return 0
		}
		for {
			n, err := linux.send(linux.Fd(s.sock), p[:pending], {.DONTWAIT, .NOSIGNAL})
			#partial switch err {
			case .NONE:
				if n > 0 && BIO_nread(s.bio, &p, cc.int(n)) == cc.int(n) {
					return n
				}
			case .EINTR:
				continue
			case .EAGAIN:
				return 0
			case:
			}
			s.failed = true
			return -1
		}
	}

	server_pollfd :: proc(
		s: ^Server_Stream,
		input: linux.Fd_Poll_Events = {.IN},
	) -> linux.Poll_Fd {
		events: linux.Fd_Poll_Events
		if .IN in input && !s.tcp_eof && BIO_ctrl_get_write_guarantee(s.bio) > 0 {
			events += {.IN, .RDHUP}
		}
		if server_pending(s) > 0 {
			events += {.OUT}
		}
		return {fd = linux.Fd(s.sock) if events != {} else -1, events = events}
	}

	poll_failed :: proc(p: linux.Poll_Fd) -> bool {
		if p.revents & {.ERR, .NVAL} != {} {
			return true
		}
		return .HUP in p.revents && .IN not_in p.events && .OUT not_in p.revents
	}

	Budget :: struct {
		start: time.Tick,
		limit: time.Duration,
	}

	poll_until :: proc(fds: []linux.Poll_Fd, budget: Budget = {}) -> Error {
		for {
			ts: linux.Time_Spec
			arg: ^linux.Time_Spec
			if budget.limit != 0 {
				remaining := budget.limit - time.tick_diff(budget.start, time.tick_now())
				if remaining <= 0 {
					return .Timeout
				}
				ts = {uint(remaining / time.Second), uint(remaining % time.Second)}
				arg = &ts
			}
			n, err := linux.ppoll(fds, arg, nil)
			if err == .EINTR {
				continue
			}
			if err != .NONE {
				return .Io
			}
			return .None if n > 0 else .Timeout
		}
	}

	@(private = "file")
	Send_Deadline :: enum {
		Absolute,
		Until_Progress,
	}

	// .Progress drains all output; WANT waits for a change that permits a retry.
	@(private = "file")
	wait_step :: proc(
		s: ^Server_Stream,
		step: Step,
		budget: ^Budget,
		clock: Send_Deadline = .Absolute,
	) -> Error {
		for {
			if time.tick_diff(budget.start, time.tick_now()) >= budget.limit {
				s.failed = true
				return .Timeout
			}
			sent := server_flush(s)
			if sent < 0 {
				return .Io
			}
			if sent > 0 && clock == .Until_Progress {
				budget.start = time.tick_now()
			}
			if step == .Progress && server_pending(s) == 0 || step == .Want_Write && sent > 0 {
				return .None
			}
			if step == .Want_Read {
				if server_fill(s) {
					return .None
				}
				if s.failed {
					return .Io
				}
			}
			if sent > 0 {
				continue
			}
			p := [1]linux.Poll_Fd{server_pollfd(s, {.IN} if step == .Want_Read else {})}
			if p[0].events == {} {
				s.failed = true
				return .Io
			}
			err := poll_until(p[:], budget^)
			if err != .None || poll_failed(p[0]) {
				s.failed = true
				return err if err != .None else .Io
			}
		}
	}

	@(private = "file")
	recv_tls :: proc(s: ^Server_Stream, buf: []u8) -> (n: int, err: Error) {
		budget := Budget{time.tick_now(), SERVER_IO_LIMIT}
		if s.read_limit != 0 {
			budget = {s.read_start, s.read_limit}
		}
		if time.tick_diff(budget.start, time.tick_now()) >= budget.limit {
			s.failed = true
			return 0, .Timeout
		}
		for {
			got, step := server_read(s, buf)
			switch step {
			case .Progress, .Closed:
				return got, .None
			case .Failed:
				return 0, .Io
			case .Want_Read, .Want_Write:
				wait_step(s, step, &budget) or_return
			}
		}
	}

	@(private = "file")
	send_tls :: proc(s: ^Server_Stream, buf: []u8) -> Error {
		budget := Budget{time.tick_now(), SERVER_IO_LIMIT}
		for pos := 0; pos < len(buf); {
			if !server_can_write(s) {
				wait_step(s, .Progress, &budget, .Until_Progress) or_return
			}
			record := buf[pos:min(pos + SERVER_RECORD_MAX, len(buf))]
			for {
				n, step := server_write(s, record)
				if step == .Progress {
					pos += n
					break
				}
				if step == .Failed || step == .Closed {
					return .Io
				}
				wait_step(s, step, &budget, .Until_Progress) or_return
			}
		}
		return wait_step(s, .Progress, &budget, .Until_Progress)
	}

	server_close :: proc(s: ^Server_Stream) {
		if s.ssl == nil {
			return
		}
		defer {
			SSL_free(s.ssl)
			BIO_free(s.bio)
			s.ssl = nil
			s.bio = nil
		}
		if s.failed {
			return
		}
		start, set := s.close_start.?
		if !set {
			start = time.tick_now()
		}
		budget := Budget{start, SERVER_CLOSE_LIMIT}
		for time.tick_diff(start, time.tick_now()) < SERVER_CLOSE_LIMIT {
			ERR_clear_error()
			r := SSL_shutdown(s.ssl)
			if r >= 0 {
				_ = wait_step(s, .Progress, &budget)
				return
			}
			step := ssl_step(s, r)
			if step == .Want_Read {
				_ = wait_step(s, .Progress, &budget)
				return
			}
			if step != .Want_Write || wait_step(s, step, &budget) != .None {
				return
			}
		}
	}
}
