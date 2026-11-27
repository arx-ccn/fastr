package tls

import cc "core:c"
import "core:encoding/hex"
import "core:sys/linux"

when ENABLED {
	foreign import libssl "system:ssl"
	foreign import libcrypto "system:crypto"

	@(private = "file")
	ASN1_Time :: struct {}
	@(private = "file")
	ASN1_String :: struct {}
	@(private = "file")
	ASN1_Object :: struct {}
	@(private = "file")
	Stack :: struct {}
	@(private = "file")
	General_Name :: struct {}
	@(private = "file")
	X509_Extension :: struct {}

	@(default_calling_convention = "c")
	foreign libssl {
		SSL_CTX_get0_certificate :: proc(ctx: ^SSL_CTX) -> ^X509 ---
	}

	@(default_calling_convention = "c")
	foreign libcrypto {
		X509_get0_notBefore :: proc(cert: ^X509) -> ^ASN1_Time ---
		X509_get0_notAfter :: proc(cert: ^X509) -> ^ASN1_Time ---
		X509_get0_serialNumber :: proc(cert: ^X509) -> ^ASN1_String ---
		ASN1_TIME_diff :: proc(days, seconds: ^cc.int, from, until: ^ASN1_Time) -> cc.int ---
		ASN1_TIME_set :: proc(t: ^ASN1_Time, seconds: cc.long) -> ^ASN1_Time ---
		ASN1_TIME_free :: proc(t: ^ASN1_Time) ---
		ASN1_STRING_length :: proc(s: ^ASN1_String) -> cc.int ---
		ASN1_STRING_get0_data :: proc(s: ^ASN1_String) -> [^]u8 ---
		X509_get_ext_d2i :: proc(cert: ^X509, nid: cc.int, crit, index: ^cc.int) -> ^Stack ---
		GENERAL_NAMES_free :: proc(s: ^Stack) ---
		OPENSSL_sk_num :: proc(s: ^Stack) -> cc.int ---
		OPENSSL_sk_value :: proc(s: ^Stack, index: cc.int) -> ^General_Name ---
		GENERAL_NAME_get0_value :: proc(n: ^General_Name, typ: ^cc.int) -> ^ASN1_String ---
		OBJ_txt2obj :: proc(text: cstring, numeric_only: cc.int) -> ^ASN1_Object ---
		ASN1_OBJECT_free :: proc(obj: ^ASN1_Object) ---
		X509_get_ext_by_OBJ :: proc(cert: ^X509, obj: ^ASN1_Object, last: cc.int) -> cc.int ---
		X509_get_ext :: proc(cert: ^X509, index: cc.int) -> ^X509_Extension ---
		X509_EXTENSION_get_critical :: proc(ext: ^X509_Extension) -> cc.int ---
		X509_EXTENSION_get_data :: proc(ext: ^X509_Extension) -> ^ASN1_String ---
	}

	Managed_Leaf :: enum {
		Application,
		Challenge,
	}

	Cert_Info :: struct {
		expires, renew: i64,
		serial:         string,
	}

	managed_ctx :: proc(
		path, domain: string,
		purpose: Managed_Leaf,
	) -> (
		^SSL_CTX,
		Cert_Info,
		Error,
	) {
		ctx, err := server_ctx(path, path)
		if err != .None {
			return nil, {}, err
		}
		info, check := inspect_leaf(SSL_CTX_get0_certificate(ctx), domain, purpose)
		if check != .None {
			SSL_CTX_free(ctx)
			return nil, {}, check
		}
		if !managed_policy(ctx, purpose) {
			SSL_CTX_free(ctx)
			return nil, {}, .Init
		}
		return ctx, info, .None
	}

	@(private = "file")
	inspect_leaf :: proc(
		cert: ^X509,
		domain: string,
		purpose: Managed_Leaf,
	) -> (
		Cert_Info,
		Error,
	) {
		if !exact_san(cert, domain) {
			return {}, .Hostname
		}
		if !valid_acme_ext(cert, purpose) {
			return {}, .Challenge_Extension
		}
		epoch := ASN1_TIME_set(nil, 0)
		if epoch == nil {
			return {}, .Init
		}
		defer ASN1_TIME_free(epoch)
		from, until: cc.int
		from_sec, until_sec: cc.int
		if ASN1_TIME_diff(&from, &from_sec, epoch, X509_get0_notBefore(cert)) != 1 ||
		   ASN1_TIME_diff(&until, &until_sec, epoch, X509_get0_notAfter(cert)) != 1 {
			return {}, .Certificate
		}
		issued := i64(from) * 86400 + i64(from_sec)
		expires := i64(until) * 86400 + i64(until_sec)
		now := cert_now()
		if issued > now || expires <= now || issued >= expires {
			return {}, .Validity
		}
		serial := X509_get0_serialNumber(cert)
		bytes := ASN1_STRING_get0_data(serial)[:ASN1_STRING_length(serial)]
		encoded := hex.encode(bytes, context.temp_allocator)
		return {expires, expires - (expires - issued) / 3, string(encoded)}, .None
	}

	cert_now :: proc "contextless" () -> i64 {
		ts, _ := linux.clock_gettime(.REALTIME)
		return i64(ts.time_sec)
	}

	@(private)
	equal_dns :: proc "contextless" (name, domain: string) -> bool {
		if len(name) != len(domain) {
			return false
		}
		for i in 0 ..< len(name) {
			b := name[i]
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b != domain[i] {
				return false
			}
		}
		return true
	}

	@(private = "file")
	exact_san :: proc(cert: ^X509, domain: string) -> bool {
		NID_SUBJECT_ALT_NAME :: 85
		GEN_DNS :: 2
		names := X509_get_ext_d2i(cert, NID_SUBJECT_ALT_NAME, nil, nil)
		if names == nil {
			return false
		}
		defer GENERAL_NAMES_free(names)
		if OPENSSL_sk_num(names) != 1 {
			return false
		}
		kind: cc.int
		name := GENERAL_NAME_get0_value(OPENSSL_sk_value(names, 0), &kind)
		if kind != GEN_DNS || name == nil || int(ASN1_STRING_length(name)) != len(domain) {
			return false
		}
		return equal_dns(string(ASN1_STRING_get0_data(name)[:len(domain)]), domain)
	}

	@(private = "file")
	valid_acme_ext :: proc(cert: ^X509, purpose: Managed_Leaf) -> bool {
		oid := OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1)
		if oid == nil {
			return false
		}
		defer ASN1_OBJECT_free(oid)
		index := X509_get_ext_by_OBJ(cert, oid, -1)
		if purpose == .Application {
			return index < 0
		}
		if index < 0 || X509_get_ext_by_OBJ(cert, oid, index) >= 0 {
			return false
		}
		ext := X509_get_ext(cert, index)
		if X509_EXTENSION_get_critical(ext) != 1 {
			return false
		}
		value := X509_EXTENSION_get_data(ext)
		if ASN1_STRING_length(value) != 34 {
			return false
		}
		der := ASN1_STRING_get0_data(value)
		return der[0] == 0x04 && der[1] == 32
	}
}
