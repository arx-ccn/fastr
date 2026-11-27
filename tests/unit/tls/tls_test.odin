// OpenSSL linkage and ClientHello extension parsing.
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

	@(test)
	test_sni_bounds :: proc(t: ^testing.T) {
		for ext in ([?][]u8{{0}, {0, 0}, {0, 1, 0}, {0, 3, 0, 0, 0}, {0, 4, 0, 0, 2, 'a'}, {0, 3, 0, 0, 1, 'a'}, {0, 4, 0, 0, 1, 0}, {0, 8, 0, 0, 1, 'a', 0, 0, 1, 'b'}}) {
			_, ok := parse_server_name(ext)
			testing.expect(t, !ok, "malformed server_name list")
		}
		name, ok := parse_server_name({0, 6, 0, 0, 3, 'a', '.', 'b'})
		testing.expect(t, ok)
		testing.expect_value(t, name, "a.b")
	}

	@(test)
	test_alpn_bounds :: proc(t: ^testing.T) {
		for ext in ([?][]u8{{0}, {0, 0}, {0, 1, 0}, {0, 2, 2, 'h'}, {0, 1, 1, 'h'}, {0, 2, 1, 'h', 1}}) {
			_, ok := parse_alpn(ext)
			testing.expect(t, !ok, "malformed ALPN list")
		}
		for offer, want in ([Acme_Offer]string{.None = "\x00\x03\x02h2", .Sole = "\x00\x0b\x0aacme-tls/1", .Mixed = "\x00\x0e\x02h2\x0aacme-tls/1"}) {
			actual, ok := parse_alpn(transmute([]u8)offer)
			testing.expect(t, ok)
			testing.expect_value(t, actual, want)
		}
	}
} else {
	@(test)
	test_disabled :: proc(t: ^testing.T) {
		_, err := connect(0, "example.com")
		testing.expect_value(t, err, Error.Disabled)
	}
}
