// Minimal OpenSSL client bindings for outbound wss:// connections.
// fastr does TLS only at the edge for inbound traffic; this exists so the
// relay-sync loop can reach wss:// peers. Blocking, one connection at a
// time — nothing else is bound.
//
// Build with -define:FASTR_TLS=false to stub the bindings out: the binary
// then links no libssl (used by the static distroless Docker image) and
// wss:// peers fail with .Disabled.
package tls

import cc "core:c"

ENABLED :: #config(FASTR_TLS, true)

when ENABLED && (ODIN_OS == .Linux || ODIN_OS == .Darwin || ODIN_OS == .FreeBSD) {
	foreign import libssl "system:ssl"
}

SSL_CTX :: struct {}
SSL :: struct {}
SSL_METHOD :: struct {}
X509 :: struct {}

Error :: enum {
	None,
	Init,
	Connect,
	Verify,
	Handshake,
	Closed,
	Io,
	// TLS support was compiled out (-define:FASTR_TLS=false).
	Disabled,
}

when ENABLED {
	@(default_calling_convention = "c")
	foreign libssl {
		TLS_client_method :: proc() -> ^SSL_METHOD ---
		SSL_CTX_new :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
		SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
		SSL_CTX_set_default_verify_paths :: proc(ctx: ^SSL_CTX) -> cc.int ---
		SSL_new :: proc(ctx: ^SSL_CTX) -> ^SSL ---
		SSL_free :: proc(ssl: ^SSL) ---
		SSL_set_fd :: proc(ssl: ^SSL, fd: cc.int) -> cc.int ---
		SSL_ctrl :: proc(ssl: ^SSL, cmd: cc.int, larg: cc.long, parg: rawptr) -> cc.long ---
		SSL_set1_host :: proc(ssl: ^SSL, hostname: cstring) -> cc.int ---
		SSL_connect :: proc(ssl: ^SSL) -> cc.int ---
		SSL_read :: proc(ssl: ^SSL, buf: [^]u8, num: cc.int) -> cc.int ---
		SSL_write :: proc(ssl: ^SSL, buf: [^]u8, num: cc.int) -> cc.int ---
		SSL_shutdown :: proc(ssl: ^SSL) -> cc.int ---
		SSL_get_verify_result :: proc(ssl: ^SSL) -> cc.long ---
	}
}

// SSL_ctrl command for setting the SNI server name (SSL_CTRL_SET_TLSEXT_HOSTNAME).
SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
TLSEXT_NAMETYPE_host_name :: 0

// X509_V_OK: peer certificate chain verified successfully.
X509_V_OK :: 0

Conn :: struct {
	ctx: ^SSL_CTX,
	ssl: ^SSL,
}

when ENABLED {
	// connect performs the TLS handshake on an already-connected TCP socket.
	// `fd` is the socket's file descriptor; `hostname` sets both the SNI
	// server name and the expected certificate hostname (verification
	// against the system trust store is always on).
	connect :: proc(fd: int, hostname: string) -> (c: Conn, err: Error) {
		c.ctx = SSL_CTX_new(TLS_client_method())
		if c.ctx == nil {
			return {}, .Init
		}
		if SSL_CTX_set_default_verify_paths(c.ctx) != 1 {
			SSL_CTX_free(c.ctx)
			return {}, .Init
		}
		c.ssl = SSL_new(c.ctx)
		if c.ssl == nil {
			SSL_CTX_free(c.ctx)
			return {}, .Init
		}
		if SSL_set_fd(c.ssl, cast(cc.int)fd) != 1 {
			shutdown(&c)
			return {}, .Init
		}
		// Hostname must outlive the handshake; clone to a NUL-terminated string.
		hbuf := make([]u8, len(hostname)+1, context.temp_allocator)
		copy(hbuf, hostname)
		host := cstring(raw_data(hbuf))
		SSL_ctrl(c.ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(host))
		SSL_set1_host(c.ssl, host)
		if SSL_connect(c.ssl) != 1 {
			shutdown(&c)
			return {}, .Handshake
		}
		if SSL_get_verify_result(c.ssl) != X509_V_OK {
			shutdown(&c)
			return {}, .Verify
		}
		return c, .None
	}

	// recv reads up to len(buf) bytes; n == 0 means the peer closed the
	// TLS connection. Mirrors net.recv_tcp semantics for the caller's loop.
	recv :: proc(c: ^Conn, buf: []u8) -> (n: int, err: Error) {
		r := SSL_read(c.ssl, raw_data(buf), cast(cc.int)len(buf))
		if r > 0 {
			return int(r), .None
		}
		return 0, .Closed
	}

	// send writes all of data, looping over partial writes.
	send :: proc(c: ^Conn, data: []u8) -> Error {
		total := 0
		for total < len(data) {
			w := SSL_write(c.ssl, raw_data(data[total:]), cast(cc.int)(len(data) - total))
			if w <= 0 {
				return .Io
			}
			total += int(w)
		}
		return .None
	}

	// shutdown sends close_notify (best effort) and frees the SSL state.
	// The underlying socket stays open; the caller closes it.
	shutdown :: proc(c: ^Conn) {
		if c.ssl != nil {
			SSL_shutdown(c.ssl)
			SSL_free(c.ssl)
			c.ssl = nil
		}
		if c.ctx != nil {
			SSL_CTX_free(c.ctx)
			c.ctx = nil
		}
	}
} else {
	connect :: proc(fd: int, hostname: string) -> (c: Conn, err: Error) {
		return {}, .Disabled
	}

	recv :: proc(c: ^Conn, buf: []u8) -> (n: int, err: Error) {
		return 0, .Disabled
	}

	send :: proc(c: ^Conn, data: []u8) -> Error {
		return .Disabled
	}

	shutdown :: proc(c: ^Conn) {}
}
