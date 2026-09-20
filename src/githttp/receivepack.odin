// git-receive-pack over smart HTTP: command-list parsing, pack ingest,
// per-ref authorization via callback (this package stays policy-free — the
// GRASP layer decides what a push may do), CAS ref updates, and
// report-status. No side-band on receive-pack; report-status is sent raw.
package githttp

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"

import "../git"

RECEIVE_PACK_CAPS :: "report-status delete-refs ofs-delta " + AGENT

// Uniquifies concurrent incoming-pack temp files (thread-per-connection).
@(private = "file")
incoming_counter: u64

// One "old new refname" push command.
Ref_Cmd :: struct {
	old:  git.Oid,
	new:  git.Oid, // ZERO_OID = delete
	name: string,
}

// Authorization callback: return one entry per command — "" allows it, any
// other string is the denial reason reported to the client.
Auth_Proc :: #type proc(user: rawptr, cmds: []Ref_Cmd) -> []string

// Allow-everything Auth_Proc (used until the GRASP policy layer is wired).
auth_allow_all :: proc(user: rawptr, cmds: []Ref_Cmd) -> []string {
	return make([]string, len(cmds), context.temp_allocator)
}

// Handle a `POST /git-receive-pack` body; the response (report-status) is
// emitted through `sink`. `max_obj` caps single inflated objects during
// pack ingest.
handle_receive_pack :: proc(
	repo: ^git.Repo,
	body: []u8,
	max_obj: int,
	auth: Auth_Proc,
	auth_user: rawptr,
	sink: git.Sink_Proc,
	sink_user: rawptr,
) -> bool {
	cmds := make([dynamic]Ref_Cmd, 0, 4, context.temp_allocator)

	r := Pkt_Reader {
		data = body,
	}
	parse: for {
		payload, kind := pkt_next(&r)
		#partial switch kind {
		case .Flush:
			break parse
		case .End, .Malformed:
			// No terminating flush: nothing to do / broken client.
			return true
		}
		line := string(payload)
		// The first command line carries client capabilities after NUL.
		if nul := strings.index_byte(line, 0); nul >= 0 {
			line = line[:nul]
		}
		line = strings.trim_suffix(line, "\n")
		if len(line) < 82 || line[40] != ' ' || line[81] != ' ' {
			return true
		}
		old, ook := git.oid_parse(line[:40])
		new, nok := git.oid_parse(line[41:81])
		name := line[82:]
		if !ook || !nok || !git.is_valid_ref_name(name) || !strings.has_prefix(name, "refs/") {
			return true
		}
		append(&cmds, Ref_Cmd{old, new, name})
	}
	if len(cmds) == 0 {
		return true
	}

	// Everything after the command flush is the packfile (absent when the
	// push only deletes refs).
	pack_data := r.data[r.pos:]
	unpack_reason := ""
	if len(pack_data) > 0 {
		tmp := fmt.aprintf(
			"%s/objects/incoming-%d-%d.pack",
			repo.path,
			os.get_pid(),
			sync.atomic_add(&incoming_counter, 1),
			allocator = context.temp_allocator,
		)
		if os.write_entire_file(tmp, pack_data) != nil {
			unpack_reason = "io error"
		} else {
			defer _ = os.remove(tmp)
			if _, ierr := git.pack_ingest(repo, tmp, max_obj, context.temp_allocator); ierr != .None {
				switch ierr {
				case .Too_Large:
					unpack_reason = "object exceeds size limit"
				case .None, .Io, .Not_Found, .Corrupt, .Invalid, .Exists, .Locked:
					unpack_reason = "unpack failed"
				}
			}
		}
	}

	results := make([]string, len(cmds), context.temp_allocator) // "" = ok
	if unpack_reason == "" {
		// Policy authorization.
		denials := auth(auth_user, cmds[:])
		for reason, i in denials {
			if reason != "" {
				results[i] = reason
			}
		}

		// Existence + connectivity for every allowed non-delete: the new tip
		// and its entire closure must be present.
		for &cmd, i in cmds {
			if results[i] != "" || cmd.new == git.ZERO_OID {
				continue
			}
			if !git.has_object(repo, cmd.new) {
				results[i] = "missing objects"
				continue
			}
			if _, cerr := git.collect_objects(repo, {cmd.new}, nil, .None, context.temp_allocator);
			   cerr != .None {
				results[i] = "missing objects"
			}
		}

		// Apply updates with CAS on the old value.
		for &cmd, i in cmds {
			if results[i] != "" {
				continue
			}
			new: Maybe(git.Oid) = cmd.new
			if cmd.new == git.ZERO_OID {
				new = nil
			}
			switch git.ref_update(repo, cmd.name, cmd.old, new) {
			case .None:
			case .Invalid:
				results[i] = "failed to update ref (stale old value)"
			case .Locked:
				results[i] = "ref locked"
			case .Io, .Not_Found, .Corrupt, .Exists, .Too_Large:
				results[i] = "internal error"
			}
		}
	}

	// report-status.
	out := make([dynamic]u8, 0, 256, context.temp_allocator)
	if unpack_reason == "" {
		pkt_write_string(&out, "unpack ok\n")
	} else {
		line := strings.concatenate({"unpack ", unpack_reason, "\n"}, context.temp_allocator)
		pkt_write_string(&out, line)
	}
	for &cmd, i in cmds {
		line: string
		if unpack_reason != "" {
			line = strings.concatenate({"ng ", cmd.name, " unpacker error\n"}, context.temp_allocator)
		} else if results[i] == "" {
			line = strings.concatenate({"ok ", cmd.name, "\n"}, context.temp_allocator)
		} else {
			line = strings.concatenate({"ng ", cmd.name, " ", results[i], "\n"}, context.temp_allocator)
		}
		pkt_write_string(&out, line)
	}
	pkt_flush(&out)
	return sink(sink_user, out[:])
}
