package main

import "core:crypto"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/linux"
import "core:time"

import "../../src/pack"
import "../../src/tls"

when tls.ENABLED {
	@(private)
	Acme_State :: struct {
		slot:   tls.Cert_Slot,
		cfg:    Acme_Config,
		worker: string,
		dir:    linux.Fd,
		wake:   linux.Fd,
		renew:  i64,
		retry:  i64,
	}

	@(private)
	acme_start_error :: proc(stage: string, err: any) -> ! {
		fmt.eprintfln("fastr: ACME startup failed: %s: %v", stage, err)
		os.exit(1)
	}

	@(private)
	prepare_acme :: proc(data_dir: string, cfg: Acme_Config) -> ^Acme_State {
		exe, err := os.get_executable_directory(context.temp_allocator)
		if err != nil {
			acme_start_error("locate fastr-acme", err)
		}
		worker := fmt.aprintf("%s/fastr-acme", exe)
		path := strings.clone_to_cstring(worker, context.temp_allocator)
		st: linux.Stat
		if linux.stat(path, &st) != .NONE ||
		   !linux.S_ISREG(st.mode) ||
		   linux.access(path, linux.X_OK) != .NONE {
			fmt.eprintln("fastr: ACME helper is missing or not executable: fastr-acme")
			os.exit(1)
		}
		state := new(Acme_State)
		state.cfg = cfg
		state.slot.domain = cfg.domain
		state.slot.bootstrap = tls.bootstrap_ctx()
		if state.slot.bootstrap == nil {
			acme_start_error("create bootstrap context", tls.Error.Init)
		}
		state.worker = worker
		state.dir = open_acme_state(data_dir, cfg)
		account, account_status := open_state_file(state.dir, "account.pem")
		if account_status == .Present {
			linux.close(account)
		} else if account_status != .Missing {
			acme_start_error("check account.pem", account_status)
		}
		state.retry = read_retry(state.dir)
		ctx, leaf, load, file := load_managed(state.dir, "live.pem", cfg.domain, .Application)
		switch file {
		case .Missing:
		case .Present:
			if load == .Validity {
				fmt.eprintln("fastr: cached ACME certificate is outside its validity period")
			} else if load != .None {
				fmt.eprintfln("fastr: cached ACME certificate is invalid: %v", load)
			} else {
				state.slot.app = ctx
				state.slot.app_until = leaf.expires
				state.renew = leaf.renew
			}
		case .Unsafe, .Io:
			acme_start_error("check live.pem", file)
		}
		wake, installed := install_hup()
		if !installed {
			acme_start_error("install signal handler", "SIGHUP setup failed")
		}
		state.wake = wake
		return state
	}

	@(private = "file")
	load_managed :: proc(
		dir: linux.Fd,
		name: cstring,
		domain: string,
		purpose: tls.Managed_Leaf,
	) -> (
		^tls.SSL_CTX,
		tls.Cert_Info,
		tls.Error,
		State_File,
	) {
		fd, status := open_state_file(dir, name)
		if status != .Present {
			return nil, {}, .None, status
		}
		defer linux.close(fd)
		ctx, leaf, err := tls.managed_ctx(fmt.tprintf("/proc/self/fd/%d", fd), domain, purpose)
		return ctx, leaf, err, .Present
	}

	@(private)
	acme_scheduler :: proc(state: ^Acme_State) {
		backoff: i64 = 0
		requested := false
		fds := [1]linux.Poll_Fd{{fd = state.wake, events = {.IN}}}
		for {
			now := tls.cert_now()
			if now >= state.retry &&
			   (state.retry != 0 ||
					   requested ||
					   now >= state.renew ||
					   now >= state.slot.app_until) {
				result := acme_attempt(state)
				if err := read_hup(state.wake); err != .NONE && err != .EAGAIN {
					fmt.eprintfln("fastr: ACME signal counter read failed: %v", err)
					return
				}
				requested = false
				if result.installed {
					backoff = 0
					persist_retry(state, 0)
				} else {
					backoff = min(max(backoff * 2, 300), 3600)
					jitter: [1]u8
					crypto.rand_bytes(jitter[:])
					persist_retry(
						state,
						max(tls.cert_now() + backoff + i64(jitter[0] % 31), state.retry),
					)
					fmt.eprintfln(
						"fastr: ACME attempt failed: %s; next attempt at Unix %d",
						result.stage,
						state.retry,
					)
				}
				free_all(context.temp_allocator)
				continue
			}
			next := state.retry if state.retry != 0 else state.renew
			wait := time.Duration(clamp(next - now, 1, 60)) * time.Second
			err := tls.poll_until(fds[:], {time.tick_now(), wait})
			if err == .Timeout {
				continue
			}
			if err != .None || tls.poll_failed(fds[0]) || read_hup(state.wake) != .NONE {
				fmt.eprintln("fastr: ACME scheduler stopped: signal watcher failed")
				return
			}
			requested = tls.cert_now() >= state.retry
		}
	}

	@(private)
	Acme_Result :: struct {
		installed: bool,
		stage:     string,
	}

	@(private = "file")
	persist_retry :: proc(state: ^Acme_State, until: i64) {
		state.retry = until
		if !write_retry(state.dir, until) {
			fmt.eprintln("fastr: ACME could not persist retry-until")
		}
	}

	@(private = "file")
	acme_attempt :: proc(state: ^Acme_State) -> Acme_Result {
		rand: [12]u8
		crypto.rand_bytes(rand[:])
		name: [len("attempt-") + 2 * len(rand) + 1]u8
		copy(name[:], "attempt-")
		pack.hex_encode(rand[:], name[len("attempt-"):len(name) - 1])
		attempt := cstring(&name[0])
		if linux.mkdirat(state.dir, attempt, transmute(linux.Mode)u32(0o700)) != .NONE {
			return {stage = "create attempt directory"}
		}
		defer if !remove_attempt(state.dir, attempt) {
			fmt.eprintln("fastr: ACME attempt directory cleanup failed")
		}
		attempt_fd, open_err := linux.openat(state.dir, attempt, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
		if open_err != .NONE {
			return {stage = "open attempt directory"}
		}
		defer linux.close(attempt_fd)

		pair: [2]linux.Fd
		sock_type := linux.Socket_Type(
			int(linux.Socket_Type.STREAM) | (1 << uint(linux.Socket_FD_Flags_Bits.CLOEXEC)),
		)
		if linux.socketpair(.UNIX, sock_type, linux.Protocol(0), &pair) != .NONE {
			return {stage = "create worker socketpair"}
		}
		child := os.new_file(uintptr(pair[1]), "fastr-acme")
		if child == nil {
			linux.close(pair[0])
			linux.close(pair[1])
			return {stage = "wrap worker socket"}
		}
		budget := tls.Budget{time.tick_now(), tls.CHALLENGE_LIMIT}
		// The child resolves the same directory inodes as the lease and installer.
		proc_fds := fmt.tprintf("/proc/%d/fd", linux.getpid())
		process, spawn_err := os.process_start(
			{
				command = {
					state.worker,
					"issue",
					state.cfg.directory,
					state.cfg.domain,
					fmt.tprintf("%s/%d", proc_fds, state.dir),
					fmt.tprintf("%s/%d", proc_fds, attempt_fd),
				},
				stdin = child,
				stdout = child,
				stderr = os.stderr,
			},
		)
		_ = os.close(child)
		if spawn_err != nil {
			linux.close(pair[0])
			return {stage = "start worker"}
		}
		res := read_worker(state, attempt_fd, pair[0], budget)
		linux.close(pair[0])
		if res.stage != "" {
			_ = os.process_kill(process)
			_, _ = os.process_wait(process)
			return res
		}
		remaining := max(time.Duration(0), budget.limit - time.tick_since(budget.start))
		status, wait_err := os.process_wait(process, remaining)
		if wait_err == .Timeout {
			_ = os.process_kill(process)
			_, _ = os.process_wait(process)
			res.stage = "worker exit timed out"
		} else if wait_err != nil || !status.success || status.exit_code != 0 {
			res.stage = "worker exited unsuccessfully"
		} else if !res.installed {
			res.stage = "worker exited without a certificate"
		}
		return res
	}

	@(private = "file")
	Order_Stage :: enum {
		Start,
		Challenge,
		Cleared,
		Installed,
		Retry,
	}

	@(private)
	read_worker :: proc(
		state: ^Acme_State,
		dir, sock: linux.Fd,
		budget: tls.Budget,
	) -> (
		res: Acme_Result,
	) {
		stage := Order_Stage.Start
		defer if stage == .Challenge {
			tls.publish_challenge(&state.slot, nil)
		}
		for {
			cmd: [1]u8
			err := worker_read(state.wake, sock, cmd[:], budget)
			if err == .Closed {
				return
			}
			if err != .None {
				res.stage =
					"read worker command" if err != .Timeout else "worker attempt timed out"
				return
			}
			switch {
			case cmd[0] == 'C' && stage == .Start:
				ctx, _, load, file := load_managed(
					dir,
					"challenge.pem",
					state.cfg.domain,
					.Challenge,
				)
				if load != .None || file != .Present {
					res.stage = "validate challenge bundle"
					return
				}
				tls.publish_challenge(&state.slot, ctx, budget.start)
				stage = .Challenge
			case cmd[0] == 'D' && stage == .Challenge:
				tls.publish_challenge(&state.slot, nil)
				stage = .Cleared
			case cmd[0] == 'I' && (stage == .Start || stage == .Cleared):
				res.stage = install_candidate(state, dir)
				if res.stage != "" {
					return
				}
				res.installed = true
				stage = .Installed
			case cmd[0] == 'R' && stage != .Installed:
				if stage == .Challenge {
					tls.publish_challenge(&state.slot, nil)
				}
				stage = .Retry
				buf: [8]u8
				if worker_read(state.wake, sock, buf[:], budget) != .None {
					res.stage = "read worker Retry-After"
					return
				}
				retry := u64(0)
				for b in buf {
					retry = retry << 8 | u64(b)
				}
				if retry > u64(max(i64)) {
					res.stage = "invalid worker Retry-After"
					return
				}
				if i64(retry) > state.retry {
					persist_retry(state, i64(retry))
				}
				continue
			case:
				res.stage = "invalid worker command order"
				return
			}
			for {
				_, send_err := linux.send(sock, {'K'}, {.DONTWAIT, .NOSIGNAL})
				if send_err == .NONE {
					break
				}
				if send_err == .EINTR ||
				   send_err == .EAGAIN && worker_wait(state.wake, sock, {.OUT}, budget) == .None {
					continue
				}
				res.stage = "acknowledge worker command"
				return
			}
		}
	}

	@(private = "file")
	install_candidate :: proc(state: ^Acme_State, dir: linux.Fd) -> string {
		ctx, leaf, load, file := load_managed(dir, "candidate.pem", state.cfg.domain, .Application)
		if load != .None || file != .Present {
			return "validate candidate bundle"
		}
		if leaf.expires <= state.slot.app_until {
			tls.SSL_CTX_free(ctx)
			return "candidate does not expire later than the current leaf"
		}
		// Move the old cooldown out of the state namespace before replacing live.pem.
		// Startup restores it if the candidate was never renamed.
		move := linux.renameat(state.dir, "retry-until", dir, "retry-until")
		if move != .NONE && move != .ENOENT {
			tls.SSL_CTX_free(ctx)
			return "stage previous retry-until"
		}
		stashed := move == .NONE
		defer if stashed && !restore_retry(state.dir, dir) {
			fmt.eprintln("fastr: ACME previous retry-until restore failed")
		}
		if stashed && (linux.fsync(dir) != .NONE || linux.fsync(state.dir) != .NONE) {
			tls.SSL_CTX_free(ctx)
			return "sync staged retry-until"
		}
		if linux.renameat(dir, "candidate.pem", state.dir, "live.pem") != .NONE {
			tls.SSL_CTX_free(ctx)
			return "replace live.pem"
		}
		stashed = false
		if linux.fsync(state.dir) != .NONE {
			fmt.eprintln("fastr: ACME live.pem renamed but state directory sync failed")
		}
		tls.publish_cert(&state.slot, ctx, leaf.expires)
		state.renew = leaf.renew
		fmt.eprintfln(
			"fastr: ACME certificate installed: %s serial=%s expiry=%d",
			state.cfg.domain,
			leaf.serial,
			leaf.expires,
		)
		return ""
	}

	@(private = "file")
	worker_read :: proc(wake, sock: linux.Fd, buf: []u8, budget: tls.Budget) -> tls.Error {
		for pos := 0; pos < len(buf); {
			if time.tick_since(budget.start) >= budget.limit {
				return .Timeout
			}
			n, err := linux.recv(sock, buf[pos:], {.DONTWAIT})
			#partial switch err {
			case .NONE:
				if n == 0 {
					return .Closed if pos == 0 else .Io
				}
				pos += n
			case .EINTR:
			case .EAGAIN:
				worker_wait(wake, sock, {.IN, .RDHUP}, budget) or_return
			case:
				return .Io
			}
		}
		return .None
	}

	@(private = "file")
	worker_wait :: proc(
		wake, sock: linux.Fd,
		events: linux.Fd_Poll_Events,
		budget: tls.Budget,
	) -> tls.Error {
		fds := [2]linux.Poll_Fd{{fd = sock, events = events}, {fd = wake, events = {.IN}}}
		tls.poll_until(fds[:], budget) or_return
		if tls.poll_failed(fds[0]) || tls.poll_failed(fds[1]) {
			return .Io
		}
		if .IN in fds[1].revents && read_hup(wake) != .NONE {
			return .Io
		}
		return .None
	}
}
