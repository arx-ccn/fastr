package tls

import "core:net"
import "core:time"

BIO :: struct {}

// The caller owns sock; the connection thread owns ssl and bio.
Server_Stream :: struct {
	sock:       net.TCP_Socket,
	ssl:        ^SSL,
	bio:        ^BIO,
	failed:     bool,
	tcp_eof:    bool,
	read_start: time.Tick,
	read_limit: time.Duration,
}

stream_recv :: proc(s: ^Server_Stream, buf: []u8) -> (n: int, err: Error) {
	got, recv_err := net.recv_tcp(s.sock, buf)
	if recv_err != nil {
		return got, .Io
	}
	return got, .None
}

stream_send :: proc(s: ^Server_Stream, buf: []u8) -> Error {
	n, err := net.send_tcp(s.sock, buf)
	if err != nil || n != len(buf) {
		return .Io
	}
	return .None
}
