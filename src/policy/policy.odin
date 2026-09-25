// Compiled policy contracts. Hooks borrow inputs and may run concurrently.
// Compose plugins with direct calls at startup; no registration or discovery.
package policy

import "core:strings"

import "../nostr"
import "../pack"

Source :: enum {Client, Peer, Import}
Operation :: enum {Req, Count, Neg_Open}
Visibility :: enum {Hide, Show}
Reason :: enum {Allow, Blocked, Restricted, Auth_Required, Rate_Limited, Invalid, Error}

Principal :: struct {
	source:   Source,
	conn_id:  u64,
	auth_pks: [][32]u8,
	peer:     string,
}

// Zero means allow; every other reason denies. Messages omit the wire prefix.
Decision :: struct {
	reason:  Reason,
	message: string,
}

Read_Hook :: #type proc(user: rawptr, principal: ^Principal, ev: ^pack.Event_View) -> Visibility

Hooks :: struct {
	user:          rawptr,
	check_write:   proc(user: rawptr, principal: ^Principal, ev: ^pack.Event) -> Decision,
	check_request: proc(user: rawptr, principal: ^Principal, op: Operation, filters: []nostr.Filter) -> Decision,
	check_read:    Read_Hook,
	after_store:   proc(user: rawptr, principal: ^Principal, ev: ^pack.Event),
}

// Read checks are pure: query pruning and overlapping filters affect calls.
// They may run under store read locks; never reenter the store or relay.
Read_Access :: struct {
	principal: Principal,
	user:      rawptr,
	check:     Read_Hook,
}

read_packed :: proc(access: Read_Access, dp: []u8) -> (visible: bool, err: pack.Error) {
	if access.check == nil {
		return true, .None
	}
	view := pack.view_packed(dp) or_return
	principal := access.principal
	return access.check(access.user, &principal, &view) == .Show, .None
}

decision_reason :: proc(d: Decision) -> string {
	prefix: string
	switch d.reason {
	case .Allow: return ""
	case .Blocked: prefix = "blocked: "
	case .Restricted: prefix = "restricted: "
	case .Auth_Required: prefix = "auth-required: "
	case .Rate_Limited: prefix = "rate-limited: "
	case .Invalid: prefix = "invalid: "
	case .Error: prefix = "error: "
	}
	message := d.message
	if message == "" {
		message = "policy denied"
	}
	return strings.concatenate({prefix, message}, context.temp_allocator)
}
