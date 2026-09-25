package pack

import "core:testing"

@(test)
test_policy_views :: proc(t: ^testing.T) {
	ev := Event{kind = 1, created_at = 123, content = "deadbeefdeadbeef", tags = {{fields = {"p", "abcdefabcdefabcd"}}, {fields = {"-"}}}}
	parsed := view_event(&ev)
	for encode in ([2]proc(^Event, ^[dynamic]u8) -> Error{serialize, serialize_fast}) {
		buf := make([dynamic]u8, context.temp_allocator)
		testing.expect_value(t, encode(&ev, &buf), Error.None)
		packed, err := view_packed(buf[:])
		testing.expect_value(t, err, Error.None)
		for view in ([2]Event_View{parsed, packed}) {
			view := view
			testing.expect_value(t, view.kind, ev.kind)
			testing.expect_value(t, view.created_at, ev.created_at)
			content, cerr := view_content(&view)
			testing.expect_value(t, cerr, Error.None)
			testing.expect_value(t, content, ev.content)
			tags, terr := view_tags(&view)
			testing.expect_value(t, terr, Error.None)
			testing.expect_value(t, len(tags), 2)
			testing.expect_value(t, tags[0].fields[1], ev.tags[0].fields[1])
			testing.expect_value(t, tags[1].fields[0], "-")
		}
		for n in 0 ..< len(buf) {
			view, verr := view_packed(buf[:n])
			if verr != .None {
				continue
			}
			_, cerr := view_content(&view)
			testing.expect(t, cerr != .None, "truncated content must fail")
			_, _ = view_tags(&view) // Truncated tag sections must not panic.
		}
	}
}
