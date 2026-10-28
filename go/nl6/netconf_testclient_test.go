/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testPKI is a CA plus a certificate it issued, for the mutual-TLS tests.
type testPKI struct {
	caPEM   []byte
	ca      *x509.Certificate
	caKey   *rsa.PrivateKey
	client  tls.Certificate
	caCount int64
}

func newTestPKI(t *testing.T, cn string) *testPKI {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn + "-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca: ca, caKey: key}
	p.client = p.issue(t, cn, x509.ExtKeyUsageClientAuth)
	return p
}

func (p *testPKI) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	_, _, cert := p.issuePEM(t, cn, usage)
	return cert
}

// issuePEM is issue that also returns the PEM encodings, for handing the
// certificate to an external client or to NetconfSubsystemConfig.
func (p *testPKI) issuePEM(t *testing.T, cn string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte, cert tls.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.caCount++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.caCount + 1),
		Subject:      pkix.Name{CommonName: cn},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		// libnetconf2 matches the host it dialled against DNS names only,
		// so the address is a DNS SAN as well for the netopeer2-cli check.
		DNSNames:    []string{"127.0.0.1"},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, cert
}

// startTestNetconf runs a real NETCONF server for a synthetic device with
// ifCount interfaces on 127.0.0.1, through startNetconfServer itself.
func startTestNetconf(t *testing.T, ifCount int, cfg NetconfSubsystemConfig) (*SimulatorManager, *DeviceSimulator, string) {
	t.Helper()
	return startTestNetconfWith(t, ifCount, cfg, nil)
}

// startTestNetconfWith is startTestNetconf with prep run on the device
// before its server starts, which is when the server fixes the interface
// names it serves.
func startTestNetconfWith(t *testing.T, ifCount int, cfg NetconfSubsystemConfig, prep func(*DeviceSimulator)) (*SimulatorManager, *DeviceSimulator, string) {
	t.Helper()
	mgr := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
		sharedTLSCert:   generateTestTLSCert(t),
		sharedSSHSigner: testNetconfSSHSigner(t),
	}
	cfg.Enabled = true
	if err := mgr.StartNetconfSubsystem(cfg); err != nil {
		t.Fatalf("StartNetconfSubsystem: %v", err)
	}
	prev := manager
	manager = mgr
	t.Cleanup(func() { manager = prev })

	dev := newTestGnmiDevice(t, ifCount)
	dev.IP = net.IPv4(127, 0, 0, 1)
	if prep != nil {
		prep(dev)
	}
	mgr.devices["test"] = dev
	dev.mu.Lock()
	err := dev.startNetconfServer(0)
	dev.mu.Unlock()
	if err != nil {
		t.Fatalf("startNetconfServer: %v", err)
	}
	t.Cleanup(func() {
		dev.mu.Lock()
		dev.stopNetconfServer()
		dev.mu.Unlock()
	})
	return mgr, dev, dev.netconfServer.ln.Addr().String()
}

// ncTestConn is the client's transport: a TLS connection, or an SSH
// netconf channel (sshTestConn).
type ncTestConn interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

// ncTestClient is a minimal NETCONF client over TLS or SSH.
type ncTestClient struct {
	t       *testing.T
	conn    ncTestConn
	rd      *netconfReader
	chunked bool
	hello   *xmlElem
	msgID   int
	// notifications received while waiting for an rpc-reply
	pending []*xmlElem
}

func dialTestNetconf(t *testing.T, addr string, cert *tls.Certificate, base11 bool) (*ncTestClient, error) {
	t.Helper()
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server's self-signed cert
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return helloTestNetconf(t, conn, base11)
}

// helloTestNetconf runs the client side of the hello exchange on conn,
// which may have been accepted from a device calling home.
func helloTestNetconf(t *testing.T, conn ncTestConn, base11 bool) (*ncTestClient, error) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	c := &ncTestClient{t: t, conn: conn, rd: newNetconfReader(conn, 16<<20)}
	msg, err := c.rd.ReadMessage()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("server hello: %w", err)
	}
	if c.hello, err = parseNetconfXML(msg); err != nil {
		t.Fatalf("server hello: %v", err)
	}
	caps := `<capability>urn:ietf:params:netconf:base:1.0</capability>`
	if base11 {
		caps += `<capability>urn:ietf:params:netconf:base:1.1</capability>`
	}
	if _, err := conn.Write(frameNetconfMessage([]byte(`<hello xmlns="`+nsNetconfBase+`"><capabilities>`+caps+`</capabilities></hello>`), false)); err != nil {
		t.Fatal(err)
	}
	c.chunked, c.rd.chunked = base11, base11
	t.Cleanup(func() { _ = conn.Close() })
	return c, nil
}

func mustDialTestNetconf(t *testing.T, addr string, cert *tls.Certificate) *ncTestClient {
	t.Helper()
	c, err := dialTestNetconf(t, addr, cert, true)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
}

func (c *ncTestClient) sendRaw(msg string) {
	c.t.Helper()
	_ = c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.conn.Write(frameNetconfMessage([]byte(msg), c.chunked)); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// next reads the next message of any kind.
func (c *ncTestClient) next(timeout time.Duration) (*xmlElem, string) {
	c.t.Helper()
	_ = c.conn.SetDeadline(time.Now().Add(timeout))
	msg, err := c.rd.ReadMessage()
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	el, err := parseNetconfXML(msg)
	if err != nil {
		c.t.Fatalf("server sent malformed XML %q: %v", msg, err)
	}
	return el, string(msg)
}

// rpc sends op and returns the rpc-reply, holding back notifications.
func (c *ncTestClient) rpc(op string) (*xmlElem, string) {
	c.t.Helper()
	c.msgID++
	c.sendRaw(fmt.Sprintf(`<rpc xmlns="%s" message-id="%d">%s</rpc>`, nsNetconfBase, c.msgID, op))
	for {
		el, raw := c.next(10 * time.Second)
		if el.Local == "notification" {
			c.pending = append(c.pending, el)
			continue
		}
		if id, _ := el.Attr("message-id"); id != fmt.Sprint(c.msgID) {
			c.t.Fatalf("reply message-id %q, want %d: %s", id, c.msgID, raw)
		}
		return el, raw
	}
}

// notification returns the next notification, held or new.
func (c *ncTestClient) notification(timeout time.Duration) (*xmlElem, string) {
	c.t.Helper()
	if len(c.pending) > 0 {
		n := c.pending[0]
		c.pending = c.pending[1:]
		return n, ""
	}
	el, raw := c.next(timeout)
	if el.Local != "notification" {
		c.t.Fatalf("expected a notification, got %s", raw)
	}
	return el, raw
}

// expectNoMessage asserts nothing arrives within d.
func (c *ncTestClient) expectNoMessage(d time.Duration) {
	c.t.Helper()
	if len(c.pending) > 0 {
		c.t.Fatalf("unexpected held notification")
	}
	_ = c.conn.SetDeadline(time.Now().Add(d))
	msg, err := c.rd.ReadMessage()
	if err == nil {
		c.t.Fatalf("unexpected message: %s", msg)
	}
	var ne net.Error
	if !asNetError(err, &ne) || !ne.Timeout() {
		c.t.Fatalf("read: %v", err)
	}
	// A timed-out TLS read poisons the connection; callers end with this.
}

func asNetError(err error, target *net.Error) bool {
	for err != nil {
		if ne, ok := err.(net.Error); ok {
			*target = ne
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// rpcError returns the reply's first rpc-error, or nil.
func rpcError(reply *xmlElem) *xmlElem {
	return reply.Child(nsNetconfBase, "rpc-error")
}

func childText(e *xmlElem, space string, path ...string) string {
	for _, p := range path {
		if e == nil {
			return ""
		}
		e = e.Child(space, p)
	}
	if e == nil {
		return ""
	}
	return e.Text
}

func mustNoRPCError(t *testing.T, reply *xmlElem, raw string) {
	t.Helper()
	if rpcError(reply) != nil {
		t.Fatalf("unexpected rpc-error: %s", raw)
	}
}

func mustRPCError(t *testing.T, reply *xmlElem, raw, tag, appTag string) {
	t.Helper()
	e := rpcError(reply)
	if e == nil {
		t.Fatalf("expected rpc-error %s, got %s", tag, raw)
	}
	if got := childText(e, nsNetconfBase, "error-tag"); got != tag {
		t.Fatalf("error-tag %q, want %q: %s", got, tag, raw)
	}
	if appTag != "" {
		if got := childText(e, nsNetconfBase, "error-app-tag"); got != appTag {
			t.Fatalf("error-app-tag %q, want %q: %s", got, appTag, raw)
		}
	}
}

// interfacesIn returns name -> entry from a data element.
func interfacesIn(data *xmlElem) map[string]*xmlElem {
	out := map[string]*xmlElem{}
	ifs := data.Child(nsIETFInterfaces, "interfaces")
	if ifs == nil {
		return out
	}
	for _, e := range ifs.Children {
		out[childText(e, nsIETFInterfaces, "name")] = e
	}
	return out
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
