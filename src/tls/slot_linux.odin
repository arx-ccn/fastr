package tls

import "core:sync"

Cert_Slot :: struct {
	mu:  sync.Mutex,
	app: ^SSL_CTX,
}

when ENABLED {
	server_ssl_new :: proc(slot: ^Cert_Slot) -> ^SSL {
		sync.guard(&slot.mu)
		return SSL_new(slot.app)
	}

	// Transfer the publication reference; existing sessions keep their own.
	publish_cert :: proc(slot: ^Cert_Slot, next: ^SSL_CTX) {
		sync.mutex_lock(&slot.mu)
		old := slot.app
		slot.app = next
		sync.mutex_unlock(&slot.mu)
		SSL_CTX_free(old)
	}
}
