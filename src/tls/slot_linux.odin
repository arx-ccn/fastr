package tls

import "core:sync"
import "core:time"

Cert_Slot :: struct {
	mu:              sync.Mutex,
	app:             ^SSL_CTX,
	bootstrap:       ^SSL_CTX,
	challenge:       ^SSL_CTX,
	domain:          string,
	app_until:       i64,
	challenge_start: time.Tick,
}

when ENABLED {
	server_ssl_new :: proc(s: ^Server_Stream, slot: ^Cert_Slot) -> ^SSL {
		sync.guard(&slot.mu)
		ctx := slot.app
		if slot.domain != "" {
			s.slot = slot
			if ctx != nil && slot.app_until > cert_now() {
				s.app_expiry = slot.app_until
			} else {
				ctx = slot.bootstrap
			}
		}
		return SSL_new(ctx) if ctx != nil else nil
	}

	// Transfer the publication reference; existing sessions keep their own.
	publish_cert :: proc(slot: ^Cert_Slot, next: ^SSL_CTX, expires: i64 = 0) {
		sync.mutex_lock(&slot.mu)
		old := slot.app
		slot.app = next
		slot.app_until = expires
		sync.mutex_unlock(&slot.mu)
		SSL_CTX_free(old)
	}

	CHALLENGE_LIMIT :: 185 * time.Second

	publish_challenge :: proc(slot: ^Cert_Slot, next: ^SSL_CTX, start: time.Tick = {}) {
		sync.mutex_lock(&slot.mu)
		old := slot.challenge
		slot.challenge = next
		slot.challenge_start = start
		sync.mutex_unlock(&slot.mu)
		SSL_CTX_free(old)
	}
}
