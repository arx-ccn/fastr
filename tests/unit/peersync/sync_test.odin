package peersync

import "core:testing"

@(test)
test_parse_server_event :: proc(t: ^testing.T) {
	raw := `["EVENT","fetch",{"id":"25ee55f1be55a10efb892fc7df07aa4127c23a993a9ada6696f23692d7aa619c","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1000,"kind":1,"tags":[],"content":"hi","sig":"43ae4dbe7ae1629704ae191ba454ee0ee61942d3f929dd7d0841abbfcd5ce8b2eb681111f11e31dba576475c6b66384eb93058d0f1e173295e2185ddfe406919"}]`
	msg := parse_server_msg(transmute([]u8)raw)
	ev, is_ev := msg.(Server_Event)
	testing.expect(t, is_ev, "expected Server_Event")
	if is_ev {
		testing.expect_value(t, ev.ev.created_at, i64(1000))
		testing.expect_value(t, ev.ev.content, "hi")
	}
}

@(test)
test_parse_eose :: proc(t: ^testing.T) {
	msg := parse_server_msg(transmute([]u8)string(`["EOSE","fetch"]`))
	_, is_eose := msg.(Server_Eose)
	testing.expect(t, is_eose, "expected Server_Eose")
}

@(test)
test_neg_err_detected :: proc(t: ^testing.T) {
	testing.expect(t, is_neg_err(transmute([]u8)string(`["NEG-ERR","sync","blocked: too many"]`)))
	testing.expect(t, !is_neg_err(transmute([]u8)string(`["NOTICE","hi"]`)))
}
