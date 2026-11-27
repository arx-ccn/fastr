package main

import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"

import "../../src/tls"

when tls.ENABLED {
	@(private = "file")
	TEST_DOMAIN :: "acme-relay.test"
	@(private = "file")
	TEST_NIP11 :: "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"

	@(private = "file")
	Route_Fixture :: struct {
		work:     string,
		listener: net.TCP_Socket,
		endpoint: string,
		state:    Acme_State,
		active:   int,
		grasp:    Grasp_Http,
	}

	@(private = "file")
	make_bundle :: proc(work, name: string, purpose: tls.Managed_Leaf) -> string {
		chain := fmt.tprintf("%s/%s.crt", work, name)
		key := fmt.tprintf("%s/%s.key", work, name)
		args := make([dynamic]string, 0, 20, context.temp_allocator)
		append(
			&args,
			"timeout",
			"5",
			"openssl",
			"req",
			"-x509",
			"-newkey",
			"ec",
			"-pkeyopt",
			"ec_paramgen_curve:P-256",
			"-nodes",
			"-days",
			"1",
			"-subj",
			"/CN=" + TEST_DOMAIN,
			"-addext",
			"subjectAltName=DNS:" + TEST_DOMAIN,
			"-keyout",
			key,
			"-out",
			chain,
		)
		if purpose == .Challenge {
			append(
				&args,
				"-addext",
				fmt.tprintf(
					"1.3.6.1.5.5.7.1.31=critical,DER:04:20%s",
					strings.repeat(":00", 32, context.temp_allocator),
				),
			)
		}
		result, _, stderr, err := os.process_exec({command = args[:]}, context.temp_allocator)
		assert(err == nil && result.exit_code == 0, string(stderr))
		pem, e1 := os.read_entire_file_from_path(chain, context.temp_allocator)
		priv, e2 := os.read_entire_file_from_path(key, context.temp_allocator)
		assert(e1 == nil && e2 == nil)
		bundle := fmt.tprintf("%s/%s.pem", work, name)
		f, e3 := os.open(bundle, {.Write, .Create, .Excl}, transmute(os.Permissions)u32(0o600))
		assert(e3 == nil)
		_, e1 = os.write(f, pem)
		_, e2 = os.write(f, priv)
		assert(e1 == nil && e2 == nil && os.close(f) == nil)
		return bundle
	}

	@(private = "file")
	fingerprint :: proc(path: string) -> string {
		result, stdout, stderr, err := os.process_exec(
			{
				command = {
					"timeout",
					"4",
					"openssl",
					"x509",
					"-in",
					path,
					"-noout",
					"-sha256",
					"-fingerprint",
				},
			},
			context.temp_allocator,
		)
		assert(err == nil && result.exit_code == 0, string(stderr))
		return strings.trim_space(string(stdout))
	}

	@(private = "file")
	accept_probe :: proc(f: ^Route_Fixture) {
		p := [1]linux.Poll_Fd{{fd = linux.Fd(f.listener), events = {.IN}}}
		if tls.poll_until(p[:], {time.tick_now(), 5 * time.Second}) != .None {
			return
		}
		sock, ok := accept_client(f.listener, &f.state.slot)
		if !ok {
			return
		}
		routes := Http_Routes {
			nip11 = TEST_NIP11,
			grasp = &f.grasp,
		}
		ctx := new(Conn_Ctx)
		ctx^ = {
			stream = {sock = sock},
			slot = &f.state.slot,
			active = &f.active,
			http = &routes,
		}
		sync.atomic_add(&f.active, 1)
		conn_entry(ctx)
	}

	@(private = "file")
	Probe_Result :: struct {
		fp, output, error: string,
		exit:              int,
	}

	@(private = "file")
	probe :: proc(f: ^Route_Fixture, options: ..string) -> Probe_Result {
		args := make([dynamic]string, 0, 13, context.temp_allocator)
		append(
			&args,
			"timeout",
			"4",
			"openssl",
			"s_client",
			"-connect",
			f.endpoint,
			"-ign_eof",
			"-showcerts",
		)
		append(&args, ..options)
		input, e := os.open(fmt.tprintf("%s/request", f.work))
		assert(e == nil)
		defer os.close(input)
		t := thread.create_and_start_with_poly_data(f, accept_probe)
		assert(t != nil)
		result, stdout, stderr, err := os.process_exec(
			{command = args[:], stdin = input},
			context.temp_allocator,
		)
		thread.join(t)
		thread.destroy(t)
		assert(err == nil)
		out := Probe_Result {
			output = string(stdout),
			error  = string(stderr),
			exit   = result.exit_code,
		}
		assert(out.exit != 124, out.error)
		if first := strings.index(out.output, "-----BEGIN CERTIFICATE-----"); first >= 0 {
			end := strings.index(out.output[first:], "-----END CERTIFICATE-----")
			assert(end >= 0)
			path := fmt.tprintf("%s/peer.pem", f.work)
			pem := out.output[first:first + end + len("-----END CERTIFICATE-----")]
			assert(os.write_entire_file(path, transmute([]u8)pem) == nil)
			out.fp = fingerprint(path)
		}
		return out
	}

	@(private = "file")
	Worker_Probe :: struct {
		state:     ^Acme_State,
		sock, dir: linux.Fd,
		result:    Acme_Result,
	}

	@(test)
	acme_challenge_isolation :: proc(t: ^testing.T) {
		work, err := os.make_directory_temp("", "fastr-acme-route-*", context.temp_allocator)
		assert(err == nil)
		defer _ = os.remove_all(work)
		attempt := fmt.tprintf("%s/attempt-eof", work)
		assert(os.make_directory(attempt) == nil)
		application := make_bundle(work, "app", .Application)
		challenge := make_bundle(attempt, "challenge", .Challenge)
		app_fp, challenge_fp := fingerprint(application), fingerprint(challenge)
		assert(app_fp != challenge_fp)
		wrong_app, _, wrong_err := tls.managed_ctx(challenge, TEST_DOMAIN, .Application)
		defer tls.SSL_CTX_free(wrong_app)
		testing.expect_value(t, wrong_err, tls.Error.Challenge_Extension)
		request ::
			"GET / HTTP/1.1\r\nHost: " +
			TEST_DOMAIN +
			"\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
		assert(
			os.write_entire_file(
				fmt.tprintf("%s/request", work),
				transmute([]u8)string(request),
			) ==
			nil,
		)

		listener, listen_err := net.listen_tcp(
			{address = net.parse_address("127.0.0.1"), port = 0},
		)
		assert(listen_err == nil)
		defer net.close(listener)
		ep, ep_err := net.bound_endpoint(listener)
		assert(ep_err == nil)
		f := Route_Fixture {
			work     = work,
			listener = listener,
			endpoint = fmt.tprintf("127.0.0.1:%d", ep.port),
		}
		f.state.wake = -1
		f.state.cfg.domain = TEST_DOMAIN
		f.state.slot.domain = TEST_DOMAIN
		f.state.slot.bootstrap = tls.bootstrap_ctx()
		assert(f.state.slot.bootstrap != nil)
		defer tls.SSL_CTX_free(f.state.slot.bootstrap)
		defer tls.publish_cert(&f.state.slot, nil)
		defer tls.publish_challenge(&f.state.slot, nil)
		chall, _, chall_err := tls.managed_ctx(challenge, TEST_DOMAIN, .Challenge)
		assert(chall_err == .None)
		tls.publish_challenge(&f.state.slot, chall, time.tick_now())

		for version in ([?]string{"-tls1_2", "-tls1_3"}) {
			r := probe(&f, version, "-servername", "ACME-Relay.test", "-alpn", "acme-tls/1")
			testing.expect_value(t, r.fp, challenge_fp)
			testing.expect(t, strings.contains(r.output, "ALPN protocol: acme-tls/1"))
			testing.expect(
				t,
				!strings.contains(r.output, "HTTP/1.1"),
				"challenge handled an HTTP request",
			)
		}
		r := probe(&f, "-servername", TEST_DOMAIN)
		testing.expect(
			t,
			r.fp == "" && r.exit != 0 && strings.contains(r.error, "handshake failure"),
		)

		app, leaf, app_err := tls.managed_ctx(application, TEST_DOMAIN, .Application)
		assert(app_err == .None)
		tls.publish_cert(&f.state.slot, app, leaf.expires)
		r = probe(&f, "-servername", TEST_DOMAIN)
		testing.expect_value(t, r.fp, app_fp)
		testing.expect(t, strings.contains(r.output, TEST_NIP11))
		r = probe(&f, "-noservername")
		testing.expect_value(t, r.fp, app_fp)
		r = probe(&f, "-servername", "wrong.test")
		testing.expect(
			t,
			r.fp == "" && r.exit != 0 && strings.contains(r.error, "unrecognized name"),
		)
		r = probe(&f, "-servername", TEST_DOMAIN, "-alpn", "acme-tls/1")
		testing.expect_value(t, r.fp, challenge_fp)
		for opts in ([?][]string{{"-noservername", "-alpn", "acme-tls/1"}, {"-servername", "wrong.test", "-alpn", "acme-tls/1"}, {"-servername", TEST_DOMAIN, "-alpn", "http/1.1,acme-tls/1"}}) {
			r = probe(&f, ..opts)
			testing.expect(t, r.fp == "" && r.exit != 0)
		}
		tls.publish_challenge(&f.state.slot, nil)
		r = probe(&f, "-servername", TEST_DOMAIN, "-alpn", "acme-tls/1")
		testing.expect(
			t,
			r.fp == "" && r.exit != 0 && strings.contains(r.error, "no application protocol"),
		)

		pair: [2]linux.Fd
		assert(linux.socketpair(.UNIX, .STREAM, linux.Protocol(0), &pair) == .NONE)
		defer linux.close(pair[0])
		dir, dir_err := linux.open(
			strings.clone_to_cstring(attempt, context.temp_allocator),
			{.DIRECTORY, .CLOEXEC},
		)
		assert(dir_err == .NONE)
		defer linux.close(dir)
		w := Worker_Probe {
			state = &f.state,
			sock  = pair[0],
			dir   = dir,
		}
		worker := thread.create_and_start_with_poly_data(&w, proc(w: ^Worker_Probe) {
			w.result = read_worker(w.state, w.dir, w.sock, {time.tick_now(), 4 * time.Second})
		})
		assert(worker != nil)
		defer thread.destroy(worker)
		n, send_err := linux.send(pair[1], {'C'}, {.NOSIGNAL})
		assert(n == 1 && send_err == .NONE)
		poll := [1]linux.Poll_Fd{{fd = pair[1], events = {.IN}}}
		assert(tls.poll_until(poll[:], {time.tick_now(), 3 * time.Second}) == .None)
		ack: [1]u8
		got, recv_err := linux.recv(pair[1], ack[:], {})
		assert(got == 1 && recv_err == .NONE && ack[0] == 'K')
		r = probe(&f, "-servername", TEST_DOMAIN, "-alpn", "acme-tls/1")
		testing.expect_value(t, r.fp, challenge_fp)
		linux.close(pair[1])
		thread.join(worker)
		testing.expect_value(t, w.result.stage, "")
		r = probe(&f, "-servername", TEST_DOMAIN, "-alpn", "acme-tls/1")
		testing.expect(
			t,
			r.fp == "" && r.exit != 0 && strings.contains(r.error, "no application protocol"),
		)
		r = probe(&f, "-servername", TEST_DOMAIN)
		testing.expect_value(t, r.fp, app_fp)
		testing.expect(t, strings.contains(r.output, TEST_NIP11))
	}
}
