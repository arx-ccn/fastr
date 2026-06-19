// Dev tool: print N signed kind-1 events as JSONL (for import testing).
// Usage: genevent [count]
package main

import "core:fmt"
import "core:os"
import "core:strconv"

import "../nostr"
import "../pack"
import secp "../secp256k1"

main :: proc() {
	count := 3
	if len(os.args) >= 2 {
		if n, ok := strconv.parse_int(os.args[1]); ok {
			count = n
		}
	}
	secp.init()
	for i in 1 ..= count {
		sk: [32]u8
		sk[31] = u8(i)
		pubkey, pk_ok := secp.test_pubkey(&sk)
		assert(pk_ok)
		ev := pack.Event {
			pubkey     = pubkey,
			created_at = i64(i) * 1000,
			kind       = 1,
			content    = fmt.tprintf("test k=1 t=%d", i * 1000),
		}
		ev.id = nostr.event_id_hash(&ev)
		sig, sign_ok := secp.test_sign(&sk, &ev.id)
		assert(sign_ok)
		ev.sig = sig

		buf := make([dynamic]u8, 0, 512, context.temp_allocator)
		append(&buf, `{"id":"`)
		pack.hex_encode_into(ev.id[:], &buf)
		append(&buf, `","pubkey":"`)
		pack.hex_encode_into(ev.pubkey[:], &buf)
		append(&buf, `","created_at":`)
		tmp: [21]u8
		append(&buf, strconv.write_int(tmp[:], ev.created_at, 10))
		append(&buf, `,"kind":1,"tags":[],"content":`)
		pack.write_json_str(ev.content, &buf)
		append(&buf, `,"sig":"`)
		pack.hex_encode_into(ev.sig[:], &buf)
		append(&buf, `"}`)
		fmt.println(string(buf[:]))
		free_all(context.temp_allocator)
	}
}
