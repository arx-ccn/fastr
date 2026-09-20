// Link test: the bindings must resolve against system libssl. A live
// handshake is exercised end-to-end by the sync package's ws:// tests
// (TLS needs a cert-bearing server; out of scope for unit tests).
package tls

import "core:testing"

when ENABLED {
	@(test)
	test_ctx_lifecycle :: proc(t: ^testing.T) {
		ctx := SSL_CTX_new(TLS_client_method())
		testing.expect(t, ctx != nil, "SSL_CTX_new failed")
		testing.expect(t, SSL_CTX_set_default_verify_paths(ctx) == 1, "verify paths failed")
		s := SSL_new(ctx)
		testing.expect(t, s != nil, "SSL_new failed")
		SSL_free(s)
		SSL_CTX_free(ctx)
	}
} else {
	@(test)
	test_disabled :: proc(t: ^testing.T) {
		_, err := connect(0, "example.com")
		testing.expect_value(t, err, Error.Disabled)
	}
}
