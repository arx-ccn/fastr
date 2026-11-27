package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"

import "../../src/tls"

@(test)
acme_config_validation :: proc(t: ^testing.T) {
	for bad in ([?]string{"", "localhost", "a..test", "-a.test", "a-.test", "a.test.", "127.0.0.1", "[::1]", "*.test", "a.test:443", "a.tést"}) {
		testing.expect(t, !valid_acme_domain(bad), bad)
	}
	testing.expect(t, valid_acme_domain("ACME-Relay.test"))
	for bad in ([?]string{"", "http://ca.test/dir", "https:///dir", "https://user@ca.test/dir", "https://ca.test/dir#", "https://ca.test:not-a-port", "https://ca.test:0/dir", "https://ca.test:65536/dir", "https://ca.test/di r"}) {
		testing.expect(t, !valid_acme_directory(bad), bad)
	}
	testing.expect(t, valid_acme_directory("https://localhost:14000/dir?test=1"))
	testing.expect(t, valid_acme_directory("https://[::1]:14000/dir"))
	testing.expect(t, !valid_acme_directory("https://ca.test/dir%ZZ"))
	testing.expect(t, valid_acme_directory("https://ca.test/dir%2Ftest"))
	testing.expect(t, !valid_acme_directory("https://ca|test/dir"))
}

when tls.ENABLED {
	@(test)
	acme_private_state :: proc(t: ^testing.T) {
		work, e := os.make_directory_temp("", "fastr-acme-state-*", context.temp_allocator)
		assert(e == nil)
		defer _ = os.remove_all(work)
		cfg := Acme_Config {
			domain    = "relay.test",
			directory = "https://ca.test/dir",
		}
		data := fmt.tprintf("%s/data", work)
		fd := open_acme_state(data, cfg)
		path_c := strings.clone_to_cstring(
			fmt.tprintf("/proc/self/fd/%d", fd),
			context.temp_allocator,
		)
		other, err := linux.open(path_c, {.DIRECTORY, .CLOEXEC})
		assert(err == .NONE)
		defer linux.close(other)
		testing.expect_value(t, linux.flock(other, {.EX, .NB}), linux.Errno.EAGAIN)
		st: linux.Stat
		assert(linux.fstat(fd, &st) == .NONE)
		testing.expect_value(t, transmute(u32)st.mode & 0o777, 0o700)

		assert(write_retry(fd, 2_000_000_000))
		testing.expect_value(t, read_retry(fd), 2_000_000_000)
		assert(write_retry(fd, 0))
		testing.expect_value(t, read_retry(fd), 0)

		assert(
			linux.symlinkat(
				strings.clone_to_cstring(work, context.temp_allocator),
				fd,
				"account.pem",
			) ==
			.NONE,
		)
		_, status := open_state_file(fd, "account.pem")
		testing.expect_value(t, status, State_File.Unsafe)
		assert(
			linux.symlinkat(
				strings.clone_to_cstring(work, context.temp_allocator),
				fd,
				"attempt-abandoned",
			) ==
			.NONE,
		)
		linux.close(fd)
		lease := open_acme_state(data, cfg)
		defer linux.close(lease)
		testing.expect_value(
			t,
			linux.fstatat(lease, "attempt-abandoned", &st, {.SYMLINK_NOFOLLOW}),
			linux.Errno.ENOENT,
		)
		_, status = open_state_file(lease, "account.pem")
		testing.expect_value(t, status, State_File.Unsafe)
	}

	@(test)
	acme_retry_recovery :: proc(t: ^testing.T) {
		work, e := os.make_directory_temp("", "fastr-acme-retry-*", context.temp_allocator)
		assert(e == nil)
		defer _ = os.remove_all(work)
		cfg := Acme_Config {
			domain    = "relay.test",
			directory = "https://ca.test/dir",
		}
		RETRY :: i64(2_000_000_000)
		for expected in ([?]i64{RETRY, 0}) {
			state := open_acme_state(work, cfg)
			assert(write_retry(state, RETRY))
			assert(linux.mkdirat(state, "attempt-crash", transmute(linux.Mode)u32(0o700)) == .NONE)
			attempt, de := linux.openat(state, "attempt-crash", {.DIRECTORY, .CLOEXEC})
			assert(de == .NONE)
			candidate, ce := linux.openat(
				attempt,
				"candidate.pem",
				{.WRONLY, .CREAT, .EXCL, .CLOEXEC},
				transmute(linux.Mode)u32(0o600),
			)
			assert(ce == .NONE)
			linux.close(candidate)
			assert(linux.renameat(state, "retry-until", attempt, "retry-until") == .NONE)
			if expected == 0 {
				assert(linux.renameat(attempt, "candidate.pem", state, "live.pem") == .NONE)
			}
			linux.close(attempt)
			linux.close(state)
			restarted := open_acme_state(work, cfg)
			testing.expect_value(t, read_retry(restarted), expected)
			linux.close(restarted)
		}
	}

	@(test)
	acme_retry_before_eof :: proc(t: ^testing.T) {
		work, e := os.make_directory_temp("", "fastr-acme-cooldown-*", context.temp_allocator)
		assert(e == nil)
		defer _ = os.remove_all(work)
		cfg := Acme_Config {
			domain    = "relay.test",
			directory = "https://ca.test/dir",
		}
		fd := open_acme_state(work, cfg)
		defer linux.close(fd)
		pair: [2]linux.Fd
		assert(linux.socketpair(.UNIX, .STREAM, linux.Protocol(0), &pair) == .NONE)
		defer linux.close(pair[0])
		Reader :: struct {
			state: Acme_State,
			fd:    linux.Fd,
		}
		reader := Reader {
			state = {dir = fd, wake = -1},
			fd = pair[0],
		}
		worker := thread.create_and_start_with_poly_data(&reader, proc(r: ^Reader) {
			_ = read_worker(&r.state, -1, r.fd, {time.tick_now(), 4 * time.Second})
		})
		assert(worker != nil)
		defer thread.destroy(worker)
		defer thread.join(worker)
		defer linux.close(pair[1])
		RETRY :: i64(2_000_000_000)
		msg: [9]u8
		msg[0] = 'R'
		for i in 0 ..< 8 {
			msg[i + 1] = u8((u64(RETRY) >> uint((7 - i) * 8)) & 0xff)
		}
		n, err := linux.send(pair[1], msg[:], {.NOSIGNAL})
		assert(n == len(msg) && err == .NONE)
		start := time.tick_now()
		for time.tick_since(start) < time.Second {
			if read_retry(fd) == RETRY {
				return
			}
			time.sleep(time.Millisecond)
		}
		testing.expect_value(t, read_retry(fd), RETRY)
	}
}
