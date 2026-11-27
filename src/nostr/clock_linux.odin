// Odin's POSIX timespec does not match 32-bit glibc clock_gettime.
#+build !i386
#+build !arm32
package nostr

import "core:sys/posix"
import "core:time"

// Current Unix timestamp in seconds.
unix_now :: proc() -> i64 {
	// libc uses the vDSO when available; core:time issues a syscall.
	ts: posix.timespec
	if posix.clock_gettime(.REALTIME, &ts) == .OK {
		return i64(ts.tv_sec)
	}
	return time.time_to_unix(time.now())
}
