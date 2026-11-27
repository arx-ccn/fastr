package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	responseLimit = 6 << 20
	accountLimit  = 4096
	alpnChallenge = "tls-alpn-01"
)

// Only local errors are safe to print verbatim.
type localError string

func (e localError) Error() string { return string(e) }

const (
	errEndpoint   = localError("expected an absolute HTTPS URL without userinfo or a fragment")
	errOrigin     = localError("ACME endpoint is outside the directory origin")
	errParent     = localError("parent disconnected")
	errAck        = localError("invalid parent acknowledgment")
	errBadAccount = localError("invalid PKCS#8 P-256 account key")
)

type origin struct {
	host string
	port uint64
}

func httpsOrigin(u *url.URL) (origin, error) {
	host := u.Hostname()
	if u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || host == "" || strings.HasSuffix(u.Host, ":") {
		return origin{}, errEndpoint
	}
	if strings.HasPrefix(u.Host, "[") {
		if addr, err := netip.ParseAddr(host); err != nil || !addr.Is6() {
			return origin{}, errEndpoint
		}
	} else if strings.Contains(host, ":") {
		return origin{}, errEndpoint
	}
	port := uint64(443)
	if p := u.Port(); p != "" {
		var err error
		port, err = strconv.ParseUint(p, 10, 16)
		if err != nil || port == 0 {
			return origin{}, errEndpoint
		}
	}
	return origin{host, port}, nil
}

func endpointOrigin(raw string) (origin, error) {
	u, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") {
		return origin{}, errEndpoint
	}
	return httpsOrigin(u)
}

func (o origin) matches(other origin) bool {
	return o.port == other.port && strings.EqualFold(o.host, other.host)
}

func (o origin) check(raw string) error {
	other, err := endpointOrigin(raw)
	if err != nil {
		return err
	}
	if !o.matches(other) {
		return errOrigin
	}
	return nil
}

func validDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

type caTransport struct {
	base       *http.Transport
	origin     origin
	retryUntil int64
}

func (t *caTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	o, err := httpsOrigin(req.URL)
	if err != nil {
		return nil, err
	}
	if !t.origin.matches(o) {
		return nil, errOrigin
	}
	res, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, localError("CA redirected the request")
	}
	if res.StatusCode >= 400 {
		now := time.Now()
		var retry int64
		for _, value := range res.Header.Values("Retry-After") {
			retry = max(retry, retryTime(value, now))
		}
		t.retryUntil = max(t.retryUntil, retry)
		if retry > now.Unix() && (res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500) {
			return nil, &acme.Error{StatusCode: res.StatusCode}
		}
	}
	if res.ContentLength > responseLimit {
		return nil, localError("CA response exceeds 6 MiB")
	}
	if res.Body == http.NoBody {
		return res, nil
	}
	// The ACME JSON decoders can stop before EOF. Check the complete body.
	body, err := io.ReadAll(io.LimitReader(res.Body, responseLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > responseLimit {
		return nil, localError("CA response exceeds 6 MiB")
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	return res, nil
}

func retryTime(value string, now time.Time) int64 {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 63); err == nil {
		if seconds == 0 || seconds >= uint64(math.MaxInt64-now.Unix()) {
			return 0
		}
		until := now.Unix() + int64(seconds)
		if now.Nanosecond() != 0 {
			until++
		}
		return until
	}
	if date, err := http.ParseTime(value); err == nil && date.After(now) {
		return date.Unix()
	}
	return 0
}

func readAccount(path string) (*ecdsa.PrivateKey, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode != syscall.S_IFREG|0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, localError("unsafe account.pem ownership, mode, type, or link count")
	}
	data, err := io.ReadAll(io.LimitReader(file, accountLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > accountLimit {
		return nil, errBadAccount
	}
	data = bytes.TrimSpace(data)
	block, rest := pem.Decode(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) || bytes.Count(data, []byte("-----BEGIN ")) != 1 || block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errBadAccount
	}
	var der asn1.RawValue
	if rest, err := asn1.Unmarshal(block.Bytes, &der); err != nil || len(rest) != 0 {
		return nil, errBadAccount
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errBadAccount
	}
	return key, nil
}

func writeBundle(path string, chain [][]byte, key any) (err error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	for _, cert := range chain {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return err
		}
	}
	if err := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return err
	}
	return file.Sync()
}

func accountKey(state, attempt string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(state, "account.pem")
	key, err := readAccount(path)
	if !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmp := filepath.Join(attempt, "account.tmp")
	if err := writeBundle(tmp, nil, key); err != nil {
		return nil, err
	}
	linkErr := os.Link(tmp, path)
	if err := os.Remove(tmp); err != nil {
		return nil, err
	}
	if errors.Is(linkErr, os.ErrExist) {
		return readAccount(path)
	}
	if linkErr != nil {
		return nil, linkErr
	}
	dir, err := os.Open(state)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return key, dir.Sync()
}

type parentLink struct {
	ack     chan struct{}
	waiting atomic.Bool
}

func (p *parentLink) readAcks(cancel context.CancelCauseFunc) {
	var b [1]byte
	for {
		if _, err := io.ReadFull(os.Stdin, b[:]); err != nil {
			cancel(errParent)
			return
		}
		if b[0] != 'K' || !p.waiting.CompareAndSwap(true, false) {
			cancel(errAck)
			return
		}
		p.ack <- struct{}{}
	}
}

func (p *parentLink) command(ctx context.Context, cmd byte) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	p.waiting.Store(true)
	if _, err := os.Stdout.Write([]byte{cmd}); err != nil {
		return errParent
	}
	select {
	case <-p.ack:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func connectAccount(ctx context.Context, client *acme.Client, origin origin) (string, error) {
	dir, err := client.Discover(ctx)
	if err != nil {
		return "discover directory", err
	}
	if dir.ExternalAccountRequired {
		return "discover directory", localError("external account binding is required")
	}
	for _, endpoint := range [...]string{dir.RegURL, dir.OrderURL, dir.NonceURL} {
		if err := origin.check(endpoint); err != nil {
			return "discover directory", err
		}
	}
	account, err := client.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		account, err = client.Register(ctx, &acme.Account{}, acme.AcceptTOS)
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			account, err = client.GetReg(ctx, "")
		}
	}
	if err != nil {
		return "register or load account", err
	}
	if account.Status != acme.StatusValid {
		return "check account", localError("account is not valid")
	}
	if err := origin.check(account.URI); err != nil {
		return "check account", err
	}
	client.KID = acme.KeyID(account.URI)
	return "", nil
}

func authorize(ctx context.Context, client *acme.Client, origin origin, parent *parentLink, authURL, domain, attempt string) (string, error) {
	if err := origin.check(authURL); err != nil {
		return "get authorization", err
	}
	auth, err := client.GetAuthorization(ctx, authURL)
	if err != nil {
		return "get authorization", err
	}
	identifier := acme.AuthzID{Type: "dns", Value: domain}
	if auth.Wildcard || auth.Identifier != identifier {
		return "check authorization", localError("authorization does not match the configured DNS name")
	}
	switch auth.Status {
	case acme.StatusValid:
		return "", nil
	case acme.StatusPending:
	default:
		return "check authorization", localError("authorization is neither pending nor valid")
	}

	var challenge *acme.Challenge
	for _, offer := range auth.Challenges {
		if offer.Type != alpnChallenge {
			continue
		}
		if challenge != nil {
			return "select challenge", localError("multiple TLS-ALPN-01 challenges")
		}
		challenge = offer
	}
	if challenge == nil {
		return "select challenge", localError("no TLS-ALPN-01 challenge")
	}
	if err := origin.check(challenge.URI); err != nil {
		return "select challenge", err
	}
	published := false
	switch challenge.Status {
	case acme.StatusValid:
	case acme.StatusPending, acme.StatusProcessing:
		if challenge.Token == "" {
			return "select challenge", localError("TLS-ALPN-01 challenge has no token")
		}
		pair, err := client.TLSALPN01ChallengeCert(challenge.Token, domain)
		if err != nil {
			return "generate challenge certificate", err
		}
		if err := writeBundle(filepath.Join(attempt, "challenge.pem"), pair.Certificate, pair.PrivateKey); err != nil {
			return "stage challenge certificate", err
		}
		if err := parent.command(ctx, 'C'); err != nil {
			return "publish challenge certificate", err
		}
		published = true
		if challenge.Status == acme.StatusPending {
			accepted, err := client.Accept(ctx, challenge)
			if err != nil {
				return "accept challenge", err
			}
			if accepted.Type != challenge.Type || accepted.URI != challenge.URI || accepted.Token != challenge.Token {
				return "accept challenge", localError("CA returned a different challenge")
			}
			switch accepted.Status {
			case acme.StatusPending, acme.StatusProcessing, acme.StatusValid:
			default:
				if accepted.Error != nil {
					return "accept challenge", accepted.Error
				}
				return "accept challenge", localError("CA returned an unusable challenge status")
			}
		}
	default:
		if challenge.Error != nil {
			return "select challenge", challenge.Error
		}
		return "select challenge", localError("TLS-ALPN-01 challenge has an unusable status")
	}

	auth, err = client.WaitAuthorization(ctx, authURL)
	if err != nil {
		return "wait for authorization", err
	}
	if auth.Status != acme.StatusValid || auth.Wildcard || auth.Identifier != identifier {
		return "check authorization", localError("CA did not validate the configured DNS name")
	}
	if published {
		if err := parent.command(ctx, 'D'); err != nil {
			return "clear challenge certificate", err
		}
	}
	return "", nil
}

func checkOrder(order *acme.Order, origin origin, domain string) error {
	if len(order.Identifiers) != 1 || order.Identifiers[0] != (acme.AuthzID{Type: "dns", Value: domain}) {
		return localError("order does not match the configured DNS name")
	}
	return origin.check(order.URI)
}

func issue(ctx context.Context, client *acme.Client, origin origin, parent *parentLink, domain, attempt string) (string, error) {
	if stage, err := connectAccount(ctx, client, origin); err != nil {
		return stage, err
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return "create order", err
	}
	if err := checkOrder(order, origin, domain); err != nil {
		return "check order", err
	}
	if order.Status == acme.StatusPending {
		if len(order.AuthzURLs) != 1 {
			return "check order", localError("expected exactly one authorization")
		}
		if stage, err := authorize(ctx, client, origin, parent, order.AuthzURLs[0], domain, attempt); err != nil {
			return stage, err
		}
	}
	if order.Status == acme.StatusPending || order.Status == acme.StatusProcessing {
		order, err = client.WaitOrder(ctx, order.URI)
		if err != nil {
			return "wait for order", err
		}
		if err := checkOrder(order, origin, domain); err != nil {
			return "check order", err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "generate certificate key", err
	}
	var chain [][]byte
	switch order.Status {
	case acme.StatusReady:
		if err := origin.check(order.FinalizeURL); err != nil {
			return "check finalize endpoint", err
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, key)
		if err != nil {
			return "generate CSR", err
		}
		chain, _, err = client.CreateCertFromOrder(ctx, order, csr, true)
		if err != nil {
			return "finalize order", err
		}
	case acme.StatusValid:
		if err := origin.check(order.CertURL); err != nil {
			return "check certificate endpoint", err
		}
		chain, err = client.FetchCert(ctx, order.CertURL, true)
		if err != nil {
			return "fetch certificate", err
		}
	default:
		if order.Error != nil {
			return "check order", order.Error
		}
		return "check order", localError("order is neither ready nor valid")
	}
	if err := validateChain(chain, key, domain); err != nil {
		return "verify candidate certificate", err
	}
	if err := writeBundle(filepath.Join(attempt, "candidate.pem"), chain, key); err != nil {
		return "stage candidate certificate", err
	}
	return "install candidate certificate", parent.command(ctx, 'I')
}

func exactDNSName(cert *x509.Certificate, domain string) bool {
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(sanOID) {
			continue
		}
		var list, name asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &list)
		if err != nil || len(rest) != 0 || list.Class != asn1.ClassUniversal || list.Tag != asn1.TagSequence || !list.IsCompound {
			return false
		}
		rest, err = asn1.Unmarshal(list.Bytes, &name)
		return err == nil && len(rest) == 0 && name.Class == asn1.ClassContextSpecific && name.Tag == 2 && !name.IsCompound && strings.EqualFold(string(name.Bytes), domain)
	}
	return false
}

func validateChain(chain [][]byte, key *ecdsa.PrivateKey, domain string) error {
	if len(chain) == 0 {
		return localError("CA returned no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return localError("invalid leaf certificate")
	}
	if !key.PublicKey.Equal(leaf.PublicKey) || !exactDNSName(leaf, domain) || leaf.IsCA {
		return localError("leaf does not match the certificate key and single configured DNS SAN")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return localError("leaf is not currently valid")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return localError("leaf does not permit digital signatures")
	}
	intermediates := x509.NewCertPool()
	previous := leaf
	for _, der := range chain[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil || previous.CheckSignatureFrom(cert) != nil {
			return localError("invalid or out-of-order certificate chain")
		}
		intermediates.AddCert(cert)
		previous = cert
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName: domain, CurrentTime: now, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func acmeProblem(err error) *acme.Error {
	var problem *acme.Error
	var order *acme.OrderError
	var auth *acme.AuthorizationError
	switch {
	case errors.As(err, &problem):
		return problem
	case errors.As(err, &order):
		return order.Problem
	case errors.As(err, &auth):
		for _, e := range auth.Errors {
			if errors.As(e, &problem) {
				return problem
			}
		}
	}
	return nil
}

func safeProblemType(problemType string) string {
	const prefix = "urn:ietf:params:acme:error:"
	kind, ok := strings.CutPrefix(problemType, prefix)
	if ok {
		switch kind {
		case "accountDoesNotExist", "alreadyRevoked", "badCSR", "badNonce", "badPublicKey",
			"badRevocationReason", "badSignatureAlgorithm", "caa", "compound", "connection", "dns",
			"externalAccountRequired", "incorrectResponse", "invalidContact", "malformed", "orderNotReady",
			"rateLimited", "rejectedIdentifier", "serverInternal", "tls", "unauthorized", "unsupportedContact",
			"unsupportedIdentifier", "userActionRequired":
			return prefix + kind
		}
	}
	return "unknown ACME problem"
}

func report(stage string, err error) {
	if p := acmeProblem(err); p != nil {
		if p.StatusCode >= 100 && p.StatusCode <= 599 {
			fmt.Fprintf(os.Stderr, "fastr-acme: %s: %s (status %d)\n", stage, safeProblemType(p.ProblemType), p.StatusCode)
		} else {
			fmt.Fprintf(os.Stderr, "fastr-acme: %s: %s\n", stage, safeProblemType(p.ProblemType))
		}
		return
	}
	var local localError
	var errno syscall.Errno
	var network net.Error
	var dns *net.DNSError
	var untrusted x509.UnknownAuthorityError
	var badCert x509.CertificateInvalidError
	var hostname x509.HostnameError
	diagnostic := "unexpected response or I/O error"
	switch {
	case errors.As(err, &local):
		diagnostic = local.Error()
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		diagnostic = "timed out"
	case errors.As(err, &dns):
		diagnostic = "cannot resolve CA hostname"
	case errors.As(err, &untrusted):
		diagnostic = "certificate chain is not trusted"
	case errors.As(err, &badCert):
		diagnostic = "certificate is not valid for server authentication"
	case errors.As(err, &hostname):
		diagnostic = "certificate does not match the hostname"
	case errors.As(err, &errno):
		diagnostic = errno.Error()
	}
	fmt.Fprintf(os.Stderr, "fastr-acme: %s: %s\n", stage, diagnostic)
}

func run(args []string) int {
	if len(args) != 6 || args[1] != "issue" || !validDomain(args[3]) || args[4] == "" || args[5] == "" {
		report("arguments", localError("expected issue <directory-url> <normalized-dns-name> <state-dir> <attempt-dir>"))
		return 1
	}
	directory, domain, state, attempt := args[2], args[3], args[4], args[5]
	origin, err := endpointOrigin(directory)
	if err != nil {
		report("directory URL", err)
		return 1
	}
	budget, stop := context.WithTimeout(context.Background(), 180*time.Second)
	defer stop()
	key, err := accountKey(state, attempt)
	if err != nil {
		report("load account key", err)
		return 1
	}
	ctx, cancel := context.WithCancelCause(budget)
	defer cancel(nil)
	parent := parentLink{ack: make(chan struct{}, 1)}
	go parent.readAcks(cancel)

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.MaxResponseHeaderBytes = responseLimit
	defer base.CloseIdleConnections()
	transport := caTransport{base: base, origin: origin}
	client := acme.Client{
		Key: key, DirectoryURL: directory,
		HTTPClient: &http.Client{
			Transport: &transport, Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	stage, err := issue(ctx, &client, origin, &parent, domain, attempt)
	if err == nil {
		return 0
	}
	cause := context.Cause(ctx)
	if cause == errParent || cause == errAck {
		err = cause
	} else if transport.retryUntil != 0 {
		var msg [9]byte
		msg[0] = 'R'
		binary.BigEndian.PutUint64(msg[1:], uint64(transport.retryUntil))
		_, _ = os.Stdout.Write(msg[:])
	}
	report(stage, err)
	return 1
}

func main() { os.Exit(run(os.Args)) }
