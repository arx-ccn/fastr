package main

import "core:fmt"
import "core:net"
import "core:os"
import "core:sys/linux"
import "core:sys/posix"
import "core:thread"

import "../../src/tls"

when tls.ENABLED {
	@(private = "file")
	Manual_TLS :: struct {
		slot: tls.Cert_Slot,
		cert: string,
		key:  string,
		wake: linux.Fd,
	}

	// Set before sigaction; never changed while the handler is installed.
	@(private = "file")
	hup_fd: linux.Fd

	@(private = "file")
	tls_hup :: proc "c" (_: posix.Signal) {
		one: u64 = 1
		for {
			_, err := linux.write(hup_fd, ((^[8]u8)(&one))[:])
			if err != .EINTR {
				return
			}
		}
	}

	@(private)
	install_hup :: proc() -> (linux.Fd, bool) {
		fd, err := linux.eventfd(0, {.NONBLOCK, .CLOEXEC})
		if err != .NONE {
			return -1, false
		}
		hup_fd = fd
		action := posix.sigaction_t {
			sa_handler = tls_hup,
			sa_flags   = {.RESTART},
		}
		if posix.sigaction(.SIGHUP, &action, nil) != .OK {
			linux.close(fd)
			return -1, false
		}
		return fd, true
	}

	@(private)
	read_hup :: proc(fd: linux.Fd) -> linux.Errno {
		counter: u64
		for {
			_, err := linux.read(fd, ((^[8]u8)(&counter))[:])
			if err != .EINTR {
				return err
			}
		}
	}

	@(private = "file")
	manual_reload :: proc(state: ^Manual_TLS) {
		fds := [1]linux.Poll_Fd{{fd = state.wake, events = {.IN}}}
		for {
			if tls.poll_until(fds[:]) != .None || tls.poll_failed(fds[0]) {
				fmt.eprintln("fastr: TLS reload watcher stopped: poll failed")
				return
			}
			if read_hup(state.wake) != .NONE {
				fmt.eprintln("fastr: TLS reload watcher stopped: read failed")
				return
			}
			ctx, err := tls.server_ctx(state.cert, state.key)
			if err == .None {
				tls.publish_cert(&state.slot, ctx)
				fmt.eprintln("fastr: TLS certificate reloaded")
			} else {
				fmt.eprintfln("fastr: TLS reload failed: keeping current certificate (%v)", err)
			}
			free_all(context.temp_allocator)
		}
	}

	@(private)
	start_manual_tls :: proc(cert, key: string) -> ^tls.Cert_Slot {
		ctx, err := tls.server_ctx(cert, key)
		if err != .None {
			fmt.eprintfln("fastr: TLS certificate setup failed: %v", err)
			os.exit(1)
		}
		wake, installed := install_hup()
		if !installed {
			fmt.eprintln("fastr: cannot install TLS reload signal handler")
			os.exit(1)
		}
		state := new(Manual_TLS)
		state^ = {
			slot = {app = ctx},
			cert = cert,
			key = key,
			wake = wake,
		}
		if thread.create_and_start_with_poly_data(state, manual_reload, self_cleanup = true) ==
		   nil {
			fmt.eprintln("fastr: cannot start TLS reload thread")
			os.exit(1)
		}
		return &state.slot
	}
}

@(private)
accept_client :: proc(listener: net.TCP_Socket, slot: ^tls.Cert_Slot) -> (net.TCP_Socket, bool) {
	when tls.ENABLED {
		if slot != nil {
			addr: linux.Sock_Addr_Any
			fd, err := linux.accept(linux.Fd(listener), &addr, {.CLOEXEC})
			if err != .NONE {
				fmt.eprintfln("accept failed: %v; backing off", err)
				return {}, false
			}
			return net.TCP_Socket(fd), true
		}
	}
	client, _, err := net.accept_tcp(listener)
	if err != nil {
		fmt.eprintfln("accept failed: %v; backing off", err)
		return {}, false
	}
	return client, true
}
