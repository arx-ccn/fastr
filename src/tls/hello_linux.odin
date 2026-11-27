package tls

import cc "core:c"
import "core:sync"
import "core:time"

Route :: enum {
	Unset,
	Application,
	Challenge,
}

when ENABLED {
	foreign import libssl "system:ssl"

	@(private = "file")
	Hello_Callback :: #type proc "c" (ssl: ^SSL, alert: ^cc.int, arg: rawptr) -> cc.int
	@(private = "file")
	Name_Callback :: #type proc "c" (ssl: ^SSL, alert: ^cc.int, arg: rawptr) -> cc.int
	@(private = "file")
	Alpn_Callback :: #type proc "c" (
		ssl: ^SSL,
		out: ^[^]u8,
		outlen: ^u8,
		protocols: [^]u8,
		inlen: cc.uint,
		arg: rawptr,
	) -> cc.int

	@(default_calling_convention = "c")
	foreign libssl {
		SSL_CTX_set_client_hello_cb :: proc(ctx: ^SSL_CTX, cb: Hello_Callback, arg: rawptr) ---
		SSL_CTX_set_alpn_select_cb :: proc(ctx: ^SSL_CTX, cb: Alpn_Callback, arg: rawptr) ---
		SSL_CTX_callback_ctrl :: proc(ctx: ^SSL_CTX, cmd: cc.int, cb: Name_Callback) -> cc.long ---
		SSL_CTX_set_num_tickets :: proc(ctx: ^SSL_CTX, n: cc.size_t) -> cc.int ---
		SSL_client_hello_get0_ext :: proc(ssl: ^SSL, typ: cc.uint, data: ^[^]u8, len: ^cc.size_t) -> cc.int ---
		SSL_get_servername :: proc(ssl: ^SSL, typ: cc.int) -> cstring ---
		SSL_set_SSL_CTX :: proc(ssl: ^SSL, ctx: ^SSL_CTX) -> ^SSL_CTX ---
		SSL_set_ex_data :: proc(ssl: ^SSL, idx: cc.int, data: rawptr) -> cc.int ---
		SSL_get_ex_data :: proc(ssl: ^SSL, idx: cc.int) -> rawptr ---
		SSL_get0_alpn_selected :: proc(ssl: ^SSL, out: ^[^]u8, outlen: ^cc.uint) ---
	}

	@(private = "file")
	ACME_PROTOCOL :: "acme-tls/1"
	@(private = "file")
	EXT_SERVER_NAME :: 0
	@(private = "file")
	EXT_ALPN :: 16
	@(private)
	APP_DATA_INDEX :: 0

	@(private = "file")
	Alert :: enum cc.int {
		Handshake_Failure       = 40,
		Decode_Error            = 50,
		Internal_Error          = 80,
		Unrecognized_Name       = 112,
		No_Application_Protocol = 120,
	}

	bootstrap_ctx :: proc() -> ^SSL_CTX {
		ctx := server_base_ctx()
		if ctx == nil {
			return nil
		}
		if !managed_policy(ctx, .Application) {
			SSL_CTX_free(ctx)
			return nil
		}
		return ctx
	}

	@(private)
	managed_policy :: proc(ctx: ^SSL_CTX, purpose: Managed_Leaf) -> bool {
		SSL_CTRL_SET_SESS_CACHE_MODE :: 44
		SSL_SESS_CACHE_NO_INTERNAL_LOOKUP :: 0x0100
		SSL_OP_NO_TICKET :: u64(1) << 14
		SSL_CTRL_SET_TLSEXT_SERVERNAME_CB :: 53
		SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, SSL_SESS_CACHE_NO_INTERNAL_LOOKUP, nil)
		SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET)
		if SSL_CTX_set_num_tickets(ctx, 0) != 1 ||
		   SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, acknowledge_name) != 1 {
			return false
		}
		SSL_CTX_set_client_hello_cb(ctx, select_route, nil)
		if purpose == .Challenge {
			SSL_CTX_set_alpn_select_cb(ctx, select_acme_alpn, nil)
		}
		return true
	}

	@(private = "file")
	acknowledge_name :: proc "c" (ssl: ^SSL, _: ^cc.int, _: rawptr) -> cc.int {
		SSL_TLSEXT_ERR_OK :: 0
		SSL_TLSEXT_ERR_NOACK :: 3
		return(
			SSL_TLSEXT_ERR_NOACK if SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) == nil else SSL_TLSEXT_ERR_OK \
		)
	}

	@(private = "file")
	select_acme_alpn :: proc "c" (
		_: ^SSL,
		out: ^[^]u8,
		len_out: ^u8,
		protocols: [^]u8,
		len_in: cc.uint,
		_: rawptr,
	) -> cc.int {
		SSL_TLSEXT_ERR_OK :: 0
		SSL_TLSEXT_ERR_ALERT_FATAL :: 2
		if len_in != 1 + len(ACME_PROTOCOL) ||
		   protocols[0] != len(ACME_PROTOCOL) ||
		   string(protocols[1:len_in]) != ACME_PROTOCOL {
			return SSL_TLSEXT_ERR_ALERT_FATAL
		}
		out^ = raw_data(protocols[1:len_in])
		len_out^ = len(ACME_PROTOCOL)
		return SSL_TLSEXT_ERR_OK
	}

	@(private)
	challenge_selected :: proc(ssl: ^SSL) -> bool {
		data: [^]u8
		length: cc.uint
		SSL_get0_alpn_selected(ssl, &data, &length)
		return length == len(ACME_PROTOCOL) && string(data[:length]) == ACME_PROTOCOL
	}

	@(private = "file")
	reject_hello :: proc "contextless" (alert: ^cc.int, why: Alert) -> cc.int {
		alert^ = cc.int(why)
		return 0 // SSL_CLIENT_HELLO_ERROR
	}

	@(private = "file")
	select_route :: proc "c" (ssl: ^SSL, alert: ^cc.int, _: rawptr) -> cc.int {
		SSL_CLIENT_HELLO_SUCCESS :: 1
		s := (^Server_Stream)(SSL_get_ex_data(ssl, APP_DATA_INDEX))
		if s == nil || s.slot == nil {
			return reject_hello(alert, .Internal_Error)
		}
		data: [^]u8
		length: cc.size_t
		name: string
		if SSL_client_hello_get0_ext(ssl, EXT_SERVER_NAME, &data, &length) == 1 {
			ok: bool
			name, ok = parse_server_name(data[:length])
			if !ok {
				return reject_hello(alert, .Decode_Error)
			}
		}
		offer: Acme_Offer
		if SSL_client_hello_get0_ext(ssl, EXT_ALPN, &data, &length) == 1 {
			ok: bool
			offer, ok = parse_alpn(data[:length])
			if !ok {
				return reject_hello(alert, .Decode_Error)
			}
		}
		slot := s.slot
		matches := equal_dns(name, slot.domain)
		if offer == .Mixed {
			return reject_hello(alert, .No_Application_Protocol)
		}
		if offer == .Sole {
			if !matches {
				return reject_hello(alert, .Unrecognized_Name)
			}
			switch s.route {
			case .Application:
				return reject_hello(alert, .No_Application_Protocol)
			case .Challenge:
				// Keep the context already pinned before HelloRetryRequest.
				return SSL_CLIENT_HELLO_SUCCESS
			case .Unset:
			}
			sync.mutex_lock(&slot.mu)
			defer sync.mutex_unlock(&slot.mu)
			if slot.challenge == nil || time.tick_since(slot.challenge_start) >= CHALLENGE_LIMIT {
				return reject_hello(alert, .No_Application_Protocol)
			}
			if SSL_set_SSL_CTX(ssl, slot.challenge) == nil {
				return reject_hello(alert, .Internal_Error)
			}
			s.route = .Challenge
			return SSL_CLIENT_HELLO_SUCCESS
		}
		if s.route == .Challenge {
			return reject_hello(alert, .No_Application_Protocol)
		}
		if name != "" && !matches {
			return reject_hello(alert, .Unrecognized_Name)
		}
		if s.route == .Unset && s.app_expiry <= cert_now() {
			return reject_hello(alert, .Handshake_Failure)
		}
		s.route = .Application
		return SSL_CLIENT_HELLO_SUCCESS
	}

	@(private = "file")
	list_payload :: proc "contextless" (ext: []u8) -> []u8 {
		if len(ext) < 3 || (int(ext[0]) << 8 | int(ext[1])) != len(ext) - 2 {
			return nil
		}
		return ext[2:]
	}

	@(private)
	parse_server_name :: proc "contextless" (ext: []u8) -> (name: string, ok: bool) {
		list := list_payload(ext)
		if list == nil {
			return "", false
		}
		for len(list) > 0 {
			if len(list) < 3 {
				return "", false
			}
			kind := list[0]
			n := int(list[1]) << 8 | int(list[2])
			if n == 0 || n > len(list) - 3 {
				return "", false
			}
			if kind == TLSEXT_NAMETYPE_host_name {
				if name != "" {
					return "", false
				}
				for b in list[3:3 + n] {
					if b == 0 {
						return "", false
					}
				}
				name = string(list[3:3 + n])
			}
			list = list[3 + n:]
		}
		return name, true
	}

	@(private)
	Acme_Offer :: enum {
		None,
		Sole,
		Mixed,
	}

	@(private)
	parse_alpn :: proc "contextless" (ext: []u8) -> (Acme_Offer, bool) {
		list := list_payload(ext)
		if list == nil {
			return .None, false
		}
		protocols := 0
		found := false
		for len(list) > 0 {
			n := int(list[0])
			if n == 0 || n > len(list) - 1 {
				return .None, false
			}
			found = found || string(list[1:1 + n]) == ACME_PROTOCOL
			protocols += 1
			list = list[1 + n:]
		}
		if !found {
			return .None, true
		}
		return .Sole if protocols == 1 else .Mixed, true
	}
}
