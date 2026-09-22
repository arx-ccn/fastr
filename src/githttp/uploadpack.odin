// git-upload-pack over smart HTTP, protocol v0 (the Git-Protocol: version=2
// header is deliberately ignored — clients fall back to v0).
//
// Capabilities: side-band-64k, allow-{tip,reachable}-sha1-in-want, filter
// (blob:none). No multi_ack/no-done: the base protocol terminates correctly
// (clients batch haves per request and finish with "done"), just with more
// round-trips on deep incremental fetches. No shallow: `clone --depth`
// fails client-side with a clear message; GRASP does not require it.
package githttp

import "core:strings"

import "../git"

AGENT :: "agent=fastr"

UPLOAD_PACK_CAPS ::
	"side-band-64k allow-tip-sha1-in-want allow-reachable-sha1-in-want " +
	"filter no-progress " + AGENT

ZERO_HEX :: "0000000000000000000000000000000000000000"

// Build the `GET /info/refs?service=<service>` response body. HEAD (with
// its symref capability) is advertised for upload-pack only — receive-pack
// adverts list plain refs.
advertise_refs :: proc(
	repo: ^git.Repo,
	service: string,
	caps: string,
	include_head: bool,
	allocator := context.allocator,
) -> []u8 {
	buf := make([dynamic]u8, 0, 1024, allocator)

	header := strings.concatenate({"# service=", service, "\n"}, context.temp_allocator)
	pkt_write_string(&buf, header)
	pkt_flush(&buf)

	refs := git.refs_list(repo, context.temp_allocator)

	full_caps := caps
	head_target, head_detached, head_ok := git.head_read(repo, context.temp_allocator)
	head_oid: git.Oid
	have_head := false
	if include_head && head_ok && !head_detached {
		if oid, rok := git.ref_read(repo, head_target); rok {
			head_oid = oid
			have_head = true
			full_caps = strings.concatenate(
				{caps, " symref=HEAD:", head_target},
				context.temp_allocator,
			)
		}
	}

	first := true
	line_buf := make([dynamic]u8, 0, 256, context.temp_allocator)
	write_ref_line :: proc(
		buf: ^[dynamic]u8,
		line_buf: ^[dynamic]u8,
		oid: git.Oid,
		name: string,
		caps: string,
		first: bool,
	) {
		clear(line_buf)
		hex_buf: [40]u8
		git.oid_hex_into(oid, hex_buf[:])
		append(line_buf, ..hex_buf[:])
		append(line_buf, ' ')
		append(line_buf, name)
		if first {
			append(line_buf, u8(0))
			append(line_buf, caps)
		}
		append(line_buf, '\n')
		pkt_write(buf, line_buf[:])
	}

	if have_head {
		write_ref_line(&buf, &line_buf, head_oid, "HEAD", full_caps, true)
		first = false
	}
	for ref in refs {
		write_ref_line(&buf, &line_buf, ref.oid, ref.name, full_caps, first)
		first = false
	}
	if first {
		// Empty repository: capabilities ride on a placeholder line.
		clear(&line_buf)
		append(&line_buf, ZERO_HEX)
		append(&line_buf, " capabilities^{}")
		append(&line_buf, u8(0))
		append(&line_buf, full_caps)
		append(&line_buf, '\n')
		pkt_write(&buf, line_buf[:])
	}
	pkt_flush(&buf)
	return buf[:]
}

@(private = "file")
Upload_Pack_Request :: struct {
	wants:    [dynamic]git.Oid,
	haves:    [dynamic]git.Oid,
	filter:   git.Filter,
	done:     bool,
	sideband: bool,
	// Non-empty when the request asked for something we refuse to serve.
	error:    string,
}

@(private = "file")
parse_upload_pack_request :: proc(body: []u8) -> (req: Upload_Pack_Request, ok: bool) {
	req.wants = make([dynamic]git.Oid, 0, 4, context.temp_allocator)
	req.haves = make([dynamic]git.Oid, 0, 16, context.temp_allocator)

	r := Pkt_Reader {
		data = body,
	}
	for {
		payload, kind := pkt_next(&r)
		#partial switch kind {
		case .End:
			return req, true
		case .Malformed:
			return req, false
		case .Flush:
			continue
		}
		line := strings.trim_suffix(string(payload), "\n")
		switch {
		case strings.has_prefix(line, "want "):
			rest := line[5:]
			if len(rest) < 40 {
				return req, false
			}
			oid := git.oid_parse(rest[:40]) or_return
			append(&req.wants, oid)
			// First want line carries the client's capability choices.
			if strings.contains(rest, "side-band-64k") {
				req.sideband = true
			}
		case strings.has_prefix(line, "have "):
			if len(line) < 45 {
				return req, false
			}
			oid := git.oid_parse(line[5:45]) or_return
			append(&req.haves, oid)
		case strings.has_prefix(line, "filter "):
			switch line[7:] {
			case "blob:none":
				req.filter = .Blob_None
			case "tree:0":
				req.filter = .Tree_Zero
			case:
				req.error = "unsupported filter; use blob:none or tree:0"
			}
		case line == "done":
			req.done = true
		case strings.has_prefix(line, "shallow ") || strings.has_prefix(line, "deepen"):
			req.error = "shallow clones are not supported by this server"
		case line == "":
		// keepalive/empty line: ignore
		case:
			return req, false
		}
	}
}

// Side-band-64k framing: wraps pack bytes in band-1 pkt-lines.
@(private = "file")
Sideband_Sink :: struct {
	sink: git.Sink_Proc,
	user: rawptr,
}

@(private = "file")
sideband_write :: proc(user: rawptr, data: []u8) -> bool {
	s := (^Sideband_Sink)(user)
	rest := data
	for len(rest) > 0 {
		chunk := rest
		if len(chunk) > PKT_MAX_PAYLOAD - 1 {
			chunk = chunk[:PKT_MAX_PAYLOAD - 1]
		}
		rest = rest[len(chunk):]
		// Heap + delete per frame: a pack stream emits thousands of these
		// and the per-connection temp arena only resets at connection close.
		frame := make([dynamic]u8, 0, len(chunk) + 16, context.allocator)
		defer delete(frame)
		framed := make([dynamic]u8, 0, len(chunk) + 1, context.allocator)
		defer delete(framed)
		append(&framed, u8(1)) // band 1: pack data
		append(&framed, ..chunk)
		pkt_write(&frame, framed[:])
		if !s.sink(s.user, frame[:]) {
			return false
		}
	}
	return true
}

// Handle a `POST /git-upload-pack` body, emitting the complete response
// through `sink`. Returns false only on sink (transport) failure.
handle_upload_pack :: proc(
	repo: ^git.Repo,
	body: []u8,
	sink: git.Sink_Proc,
	user: rawptr,
) -> bool {
	send_err :: proc(sink: git.Sink_Proc, user: rawptr, msg: string) -> bool {
		buf := make([dynamic]u8, 0, len(msg) + 16, context.temp_allocator)
		line := strings.concatenate({"ERR ", msg, "\n"}, context.temp_allocator)
		pkt_write_string(&buf, line)
		return sink(user, buf[:])
	}

	req, pok := parse_upload_pack_request(body)
	if !pok {
		return send_err(sink, user, "malformed upload-pack request")
	}
	if req.error != "" {
		return send_err(sink, user, req.error)
	}
	if len(req.wants) == 0 {
		return send_err(sink, user, "no wants")
	}

	// GRASP-01 serves any available oid, including unreferenced PR data.
	for want in req.wants {
		if !git.has_object(repo, want) {
			return send_err(sink, user, "want is not available")
		}
	}

	// Common bases: haves we actually have.
	common := make([dynamic]git.Oid, 0, len(req.haves), context.temp_allocator)
	for have in req.haves {
		if git.has_object(repo, have) {
			append(&common, have)
		}
	}

	buf := make([dynamic]u8, 0, 64, context.temp_allocator)
	if !req.done {
		// Stateless negotiation round: no pack yet; the client re-posts
		// with more haves (or done) next round.
		pkt_write_string(&buf, "NAK\n")
		return sink(user, buf[:])
	}

	if len(common) > 0 {
		hex_buf: [40]u8
		git.oid_hex_into(common[0], hex_buf[:])
		line := strings.concatenate({"ACK ", string(hex_buf[:]), "\n"}, context.temp_allocator)
		pkt_write_string(&buf, line)
	} else {
		pkt_write_string(&buf, "NAK\n")
	}
	if !sink(user, buf[:]) {
		return false
	}

	objects, cerr := git.collect_objects(repo, req.wants[:], common[:], req.filter, context.temp_allocator)
	if cerr != .None {
		return send_err(sink, user, "internal error collecting objects")
	}

	if req.sideband {
		sb := Sideband_Sink{sink, user}
		if git.pack_write(repo, objects, sideband_write, &sb) != .None {
			return false
		}
		tail := make([dynamic]u8, 0, 8, context.temp_allocator)
		pkt_flush(&tail)
		return sink(user, tail[:])
	}
	return git.pack_write(repo, objects, sink, user) == .None
}
