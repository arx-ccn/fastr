package main

import "core:crypto/sha2"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/linux"

import "../../src/pack"
import "../../src/tls"

when tls.ENABLED {
	@(private)
	State_File :: enum {
		Present,
		Missing,
		Unsafe,
		Io,
	}

	@(private)
	open_acme_state :: proc(data_dir: string, cfg: Acme_Config) -> linux.Fd {
		if err := os.make_directory_all(data_dir); err != nil && err != .Exist {
			acme_start_error("create data directory", err)
		}
		data, open_err := linux.open(
			strings.clone_to_cstring(data_dir, context.temp_allocator),
			{.DIRECTORY, .CLOEXEC},
		)
		if open_err != .NONE {
			acme_start_error("open data directory", open_err)
		}
		defer linux.close(data)
		acme := private_dir(data, "acme")
		defer linux.close(acme)

		hash: sha2.Context_256
		sha2.init_256(&hash)
		sha2.update(&hash, transmute([]u8)cfg.directory)
		sha2.update(&hash, {0})
		sha2.update(&hash, transmute([]u8)cfg.domain)
		digest: [32]u8
		sha2.final(&hash, digest[:])
		name: [65]u8
		pack.hex_encode(digest[:], name[:64])
		fd := private_dir(acme, cstring(&name[0]))
		if err := linux.flock(fd, {.EX, .NB}); err != .NONE {
			acme_start_error("lock state directory", err)
		}
		if !remove_attempts(fd) {
			acme_start_error("clean abandoned attempts", "directory I/O error")
		}
		return fd
	}

	@(private = "file")
	private_dir :: proc(parent: linux.Fd, name: cstring) -> linux.Fd {
		if err := linux.mkdirat(parent, name, transmute(linux.Mode)u32(0o700));
		   err != .NONE && err != .EEXIST {
			acme_start_error("create private state directory", err)
		}
		fd, err := linux.openat(parent, name, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
		if err != .NONE {
			acme_start_error("open private state directory", err)
		}
		st: linux.Stat
		if linux.fstat(fd, &st) != .NONE ||
		   st.uid != linux.geteuid() ||
		   transmute(u32)st.mode & 0o077 != 0 {
			acme_start_error("check state directory", "unsafe owner or permissions")
		}
		return fd
	}

	@(private = "file")
	private_stat :: proc(st: ^linux.Stat) -> bool {
		return(
			linux.S_ISREG(st.mode) &&
			st.uid == linux.geteuid() &&
			st.nlink == 1 &&
			transmute(u32)st.mode & 0o7777 == 0o600 \
		)
	}

	@(private)
	open_state_file :: proc(dir: linux.Fd, name: cstring) -> (linux.Fd, State_File) {
		st: linux.Stat
		err := linux.fstatat(dir, name, &st, {.SYMLINK_NOFOLLOW})
		if err == .ENOENT {
			return -1, .Missing
		}
		if err != .NONE {
			return -1, .Io
		}
		if !private_stat(&st) {
			return -1, .Unsafe
		}
		fd, open_err := linux.openat(dir, name, {.NOFOLLOW, .CLOEXEC, .NONBLOCK})
		if open_err != .NONE {
			return -1, .Io
		}
		if linux.fstat(fd, &st) != .NONE || !private_stat(&st) {
			linux.close(fd)
			return -1, .Unsafe
		}
		return fd, .Present
	}

	@(private = "file")
	remove_attempts :: proc(dir: linux.Fd) -> bool {
		if e := linux.unlinkat(dir, ".retry-until.next", {}); e != .NONE && e != .ENOENT {
			return false
		}
		buf: [4096]u8 = ---
		for {
			n, err := linux.getdents(dir, buf[:])
			if err != .NONE || n == 0 {
				return err == .NONE
			}
			off: int
			for entry in linux.dirent_iterate_buf(buf[:n], &off) {
				name := linux.dirent_name(entry)
				if !strings.has_prefix(name, "attempt-") {
					continue
				}
				child := strings.unsafe_string_to_cstring(name)
				attempt, open_err := linux.openat(dir, child, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
				if open_err == .NONE {
					ok := restore_retry(dir, attempt)
					linux.close(attempt)
					if !ok {
						return false
					}
				}
				if !remove_attempt(dir, child) {
					return false
				}
			}
		}
	}

	// candidate.pem disappears from the attempt only when live.pem is replaced.
	@(private)
	restore_retry :: proc(state, attempt: linux.Fd) -> bool {
		st: linux.Stat
		marker := linux.fstatat(attempt, "retry-until", &st, {.SYMLINK_NOFOLLOW})
		if marker == .ENOENT {
			return true
		}
		if marker != .NONE || !private_stat(&st) {
			return false
		}
		candidate := linux.fstatat(attempt, "candidate.pem", &st, {.SYMLINK_NOFOLLOW})
		if candidate == .ENOENT {
			return true
		}
		if candidate != .NONE || !private_stat(&st) {
			return false
		}
		existing := linux.fstatat(state, "retry-until", &st, {.SYMLINK_NOFOLLOW})
		if existing == .NONE {
			return private_stat(&st)
		}
		return(
			existing == .ENOENT &&
			linux.renameat(attempt, "retry-until", state, "retry-until") == .NONE &&
			linux.fsync(state) == .NONE \
		)
	}

	@(private)
	remove_attempt :: proc(parent: linux.Fd, name: cstring) -> bool {
		fd, err := linux.openat(parent, name, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
		#partial switch err {
		case .ENOENT:
			return true
		case .ENOTDIR, .ELOOP:
			return linux.unlinkat(parent, name, {}) == .NONE
		case .NONE:
		case:
			return false
		}
		defer linux.close(fd)
		buf: [4096]u8 = ---
		for {
			n, read_err := linux.getdents(fd, buf[:])
			if read_err != .NONE {
				return false
			}
			if n == 0 {
				break
			}
			off: int
			for entry in linux.dirent_iterate_buf(buf[:n], &off) {
				child := linux.dirent_name(entry)
				if child != "." &&
				   child != ".." &&
				   !remove_attempt(fd, strings.unsafe_string_to_cstring(child)) {
					return false
				}
			}
		}
		return linux.unlinkat(parent, name, {.REMOVEDIR}) == .NONE
	}

	@(private)
	read_retry :: proc(dir: linux.Fd) -> i64 {
		fd, status := open_state_file(dir, "retry-until")
		if status == .Missing {
			return 0
		}
		if status != .Present {
			acme_start_error("check retry-until", status)
		}
		defer linux.close(fd)
		buf: [32]u8 = ---
		for {
			n, err := linux.read(fd, buf[:])
			if err == .EINTR {
				continue
			}
			if err == .NONE && n > 1 && n < len(buf) && buf[n - 1] == '\n' {
				if unix, ok := strconv.parse_i64(string(buf[:n - 1])); ok && unix > 0 {
					return unix
				}
			}
			acme_start_error("read retry-until", "invalid retry timestamp")
		}
	}

	@(private)
	write_retry :: proc(dir: linux.Fd, unix: i64) -> bool {
		if unix == 0 {
			err := linux.unlinkat(dir, "retry-until", {})
			return err == .ENOENT || err == .NONE && linux.fsync(dir) == .NONE
		}
		next :: ".retry-until.next"
		fd, err := linux.openat(
			dir,
			next,
			{.WRONLY, .CREAT, .EXCL, .NOFOLLOW, .CLOEXEC},
			transmute(linux.Mode)u32(0o600),
		)
		if err != .NONE {
			return false
		}
		defer linux.unlinkat(dir, next, {})
		defer linux.close(fd)
		text := fmt.tprintf("%d\n", unix)
		for rest := transmute([]u8)text; len(rest) > 0; {
			n, write_err := linux.write(fd, rest)
			if write_err == .EINTR {
				continue
			}
			if write_err != .NONE || n <= 0 {
				return false
			}
			rest = rest[n:]
		}
		return(
			linux.fsync(fd) == .NONE &&
			linux.renameat(dir, next, dir, "retry-until") == .NONE &&
			linux.fsync(dir) == .NONE \
		)
	}
}
