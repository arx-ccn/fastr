package ws

import "core:sync"
import "core:sync/chan"
import "core:sys/linux"
import "core:time"

import "../nostr"
import "../tls"

when tls.ENABLED {
	@(private = "file")
	Tls_Output :: struct {
		msg:     Out_Msg,
		parts:   [2][]u8,
		scratch: [WRITE_STACK_LIMIT + MAX_FRAME_HEADER_LEN]u8,
		json:    [dynamic]u8,
	}

	@(private = "file")
	tls_take :: proc(o: ^Outbox) -> Out_Msg {
		sync.guard(&o.send_mu)
		msg, _ := chan.try_recv(o.ch)
		return msg
	}

	@(private = "file")
	Retire :: enum {
		Sent,
		Discard,
	}

	@(private = "file")
	tls_retire :: proc(cs: ^Conn_State, out: ^Tls_Output, result: Retire) {
		if out.msg == nil {
			return
		}
		batch, is_batch := out.msg.(Out_Batch)
		if result == .Sent &&
		   is_batch &&
		   cap(cs.replay_spare) == 0 &&
		   cap(batch.wire) <= 256 * 1024 {
			clear(&batch.wire)
			cs.replay_spare = batch.wire
		} else {
			drop_msg(out.msg)
		}
		out.msg = nil
		sync.guard(&cs.outbox.send_mu)
		cs.outbox.pending -= 1
	}

	@(private = "file")
	tls_prepare :: proc(cs: ^Conn_State, out: ^Tls_Output) {
		#partial switch m in out.msg {
		case Out_Batch:
			out.parts[0] = m.wire[m.sent:]
		case Out_Pong:
			out.parts[0] = encode_frame(out.scratch[:], .Pong, m.payload)
		case Out_Live:
			if !live_allowed(cs, m.live) {
				return
			}
			clear(&out.json)
			nostr.write_event_head(m.live.sub_id, &out.json)
			append(&out.json, ..m.live.shared.json)
			if len(out.json) <= WRITE_STACK_LIMIT {
				out.parts[0] = encode_frame(out.scratch[:], .Text, out.json[:])
			} else {
				n := encode_frame_header(out.scratch[:], .Text, len(out.json))
				out.parts = {out.scratch[:n], out.json[:]}
			}
		}
	}

	@(private = "file")
	tls_write_part :: proc(cs: ^Conn_State, out: ^Tls_Output) -> tls.Step {
		part := out.parts[0]
		n, step := tls.server_write(cs.conn.stream, part[:min(len(part), tls.SERVER_RECORD_MAX)])
		if step != .Progress {
			return step
		}
		out.parts[0] = part[n:]
		if len(out.parts[0]) == 0 {
			out.parts = {out.parts[1], nil}
			if len(out.parts[0]) == 0 {
				tls_retire(cs, out, .Sent)
			}
		}
		return .Progress
	}

	@(private)
	tls_ws_loop :: proc(cs: ^Conn_State) {
		s := cs.conn.stream
		o := cs.outbox
		wake := o.wake.?
		out: Tls_Output
		defer {
			if s.close_start == nil {
				close_outbox(cs)
			}
			tls_retire(cs, &out, .Discard)
			for {
				msg, ok := chan.try_recv(o.ch)
				if !ok {
					break
				}
				drop_msg(msg)
			}
			delete(out.json)
			sync.guard(&o.send_mu)
			o.pending = 0
		}

		rstep, wstep := tls.Step.Progress, tls.Step.Progress
		dst: []u8
		terminal: u16
		write_budget: tls.Budget
		for {
			if out.msg == nil && len(out.parts[0]) == 0 {
				out.msg = tls_take(o)
			}
			now := time.tick_now()
			pending := tls.server_pending(s)
			close_start, draining := s.close_start.?
			if out.msg == nil && len(out.parts[0]) == 0 && pending == 0 {
				write_budget = {}
				if draining && terminal == 0 {
					return
				}
			} else if write_budget.limit == 0 {
				write_budget = {now, tls.SERVER_IO_LIMIT}
			}
			budget := write_budget
			if draining {
				budget = {close_start, tls.SERVER_CLOSE_LIMIT}
			}
			if budget.limit != 0 && time.tick_diff(budget.start, now) >= budget.limit {
				s.failed = true
				return
			}

			sent := tls.server_flush(s)
			if sent < 0 {
				return
			}
			if sent > 0 && !draining {
				write_budget.start = time.tick_now()
				budget = write_budget
			}
			filled := rstep != .Closed && tls.server_fill(s)
			if s.failed {
				return
			}
			progress := sent > 0 || filled

			// A stalled write owns its buffer. WANT_WRITE also excludes SSL_read.
			retried := wstep == .Want_Write && sent > 0 || wstep == .Want_Read && filled
			if retried {
				wstep = tls_write_part(cs, &out)
				if wstep == .Closed || wstep == .Failed {
					return
				}
			}
			incoming: Incoming
			parse_err: Error
			if !draining {
				incoming, parse_err = conn_parse(&cs.conn)
			}
			if incoming.event == .Close || parse_err != .None {
				s.close_start = time.tick_now()
				close_outbox(cs)
				terminal =
					incoming.close_code if parse_err == .None else close_code_for_error(parse_err)
				continue
			}
			if incoming.event != .None {
				consume_incoming(cs, incoming)
				progress = true
			} else if wstep != .Want_Write &&
			   (rstep == .Progress ||
					   rstep == .Want_Read && filled ||
					   rstep == .Want_Write && sent > 0) {
				if dst == nil {
					dst = cs.conn.rbuf[:] if draining else conn_read_buf(&cs.conn)
				}
				n: int
				n, rstep = tls.server_read(s, dst)
				switch rstep {
				case .Progress:
					if !draining {
						cs.conn.rend += n
					}
					dst = nil
					progress = true
				case .Closed:
					if !draining {
						return
					}
				// The peer ended its TLS writes after requesting a WS close.
				// Finish the already-started drain without reading again.
				case .Failed:
					return
				case .Want_Read, .Want_Write:
				}
			}

			if !retried && rstep != .Want_Write && wstep == .Progress && tls.server_can_write(s) {
				if len(out.parts[0]) == 0 {
					if out.msg != nil {
						tls_prepare(cs, &out)
						if len(out.parts[0]) == 0 {
							tls_retire(cs, &out, .Discard)
							continue
						}
					} else if draining && terminal != 0 {
						out.parts[0] = encode_close(out.scratch[:], terminal, "")
						terminal = 0
					}
				}
				if len(out.parts[0]) != 0 {
					wstep = tls_write_part(cs, &out)
					if wstep == .Closed || wstep == .Failed {
						return
					}
					// Even on WANT, the SSL operation may have queued control bytes.
					progress = true
				}
			}
			if progress {
				continue
			}

			fds := [2]linux.Poll_Fd {
				tls.server_pollfd(s, {} if rstep == .Closed else {.IN}),
				{fd = -1},
			}
			if .OUT in fds[0].events && budget.limit == 0 {
				// SSL_read can queue protocol bytes even without delivering a frame.
				write_budget = {time.tick_now(), tls.SERVER_IO_LIMIT}
				budget = write_budget
			}
			if !draining && out.msg == nil {
				fds[1] = {
					fd     = wake,
					events = {.IN},
				}
			}
			if fds[0].fd == -1 && fds[1].fd == -1 ||
			   tls.poll_until(fds[:], budget) != .None ||
			   tls.poll_failed(fds[0]) ||
			   tls.poll_failed(fds[1]) {
				s.failed = true
				return
			}
			if .IN in fds[1].revents {
				counter: u64
				for {
					_, err := linux.read(wake, ((^[8]u8)(&counter))[:])
					if err == .EINTR {
						continue
					}
					if err != .NONE && err != .EAGAIN {
						s.failed = true
						return
					}
					break
				}
			}
		}
	}
}
