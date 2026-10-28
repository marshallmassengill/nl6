/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testCallHomeCollector is the Call Home client side: it accepts the TCP
// connections devices open and is the TLS client on them.
type testCallHomeCollector struct {
	ln    net.Listener
	conns chan net.Conn
}

func newTestCallHomeCollector(t *testing.T) *testCallHomeCollector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &testCallHomeCollector{ln: ln, conns: make(chan net.Conn, 16)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.conns <- conn
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

func (c *testCallHomeCollector) addr() string { return c.ln.Addr().String() }

func (c *testCallHomeCollector) accept(t *testing.T, timeout time.Duration) net.Conn {
	t.Helper()
	select {
	case conn := <-c.conns:
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	case <-time.After(timeout):
		t.Fatalf("no Call Home connection within %s", timeout)
		return nil
	}
}

// session accepts the next connection and runs TLS and the hello on it.
func (c *testCallHomeCollector) session(t *testing.T, cert *tls.Certificate) *ncTestClient {
	t.Helper()
	raw := c.accept(t, 5*time.Second)
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server's self-signed cert
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	nc, err := helloTestNetconf(t, tls.Client(raw, cfg), true)
	if err != nil {
		t.Fatalf("Call Home session: %v", err)
	}
	return nc
}

func TestNetconfCallHomeAddress(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"collector.example", "collector.example:4335"},
		{"10.0.0.5", "10.0.0.5:4335"},
		{"10.0.0.5:9000", "10.0.0.5:9000"},
		{" 10.0.0.5:9000 ", "10.0.0.5:9000"},
		{"::1", "[::1]:4335"},
		{"[::1]", "[::1]:4335"},
		{"[::1]:9000", "[::1]:9000"},
	} {
		got, err := netconfCallHomeAddress(tc.in, netconfCallHomeDefaultPort)
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", ":4335", "host:0", "host:65536", "host:port", "a b:1", "http://x"} {
		if got, err := netconfCallHomeAddress(bad, netconfCallHomeDefaultPort); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestParseNetconfConfiguredSubscriptions(t *testing.T) {
	got, err := parseNetconfConfiguredSubscriptions(" stream, periodic=30s ,on-change,")
	if err != nil {
		t.Fatal(err)
	}
	want := []netconfConfiguredSubscription{
		{ID: 1, Kind: netconfConfiguredStream},
		{ID: 2, Kind: netconfConfiguredPeriodic, Period: 30 * time.Second},
		{ID: 3, Kind: netconfConfiguredOnChange},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, err := parseNetconfConfiguredSubscriptions(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v, %v", got, err)
	}
	for _, bad := range []string{
		"streams", "periodic", "periodic=", "periodic=500ms", "periodic=1.005s", "periodic=x",
		"stream,stream", "periodic=1s,periodic=1000ms",
		"periodic=1s,periodic=2s,periodic=3s,periodic=4s,periodic=5s,periodic=6s,periodic=7s,periodic=8s,periodic=9s",
	} {
		if got, err := parseNetconfConfiguredSubscriptions(bad); err == nil {
			t.Errorf("%q accepted as %v", bad, got)
		}
	}
}

func TestNetconfCallHomeConfigIsValidatedAtStart(t *testing.T) {
	for _, cfg := range []NetconfSubsystemConfig{
		{CallHomeSubscriptions: "stream"}, // configured subscriptions need a receiver
		{CallHome: "host:0"},
		{CallHome: "host", CallHomeSubscriptions: "nonsense"},
	} {
		mgr := &SimulatorManager{sharedTLSCert: generateTestTLSCert(t)}
		cfg.Enabled = true
		if err := mgr.StartNetconfSubsystem(cfg); err == nil {
			t.Errorf("%+v: accepted", cfg)
		}
	}
}

// TestNetconfCallHomeServesNETCONFAndRedials: the device dials the
// client, is the TLS server on the connection, serves the same operations
// as on its listener, and dials again when the session ends.
func TestNetconfCallHomeServesNETCONFAndRedials(t *testing.T) {
	pki := newTestPKI(t, "callhome-client")
	col := newTestCallHomeCollector(t)
	mgr, _, _ := startTestNetconf(t, 2, NetconfSubsystemConfig{CallHome: col.addr()})

	c := col.session(t, &pki.client)
	if childText(c.hello, nsNetconfBase, "session-id") == "" {
		t.Fatal("server hello has no session-id")
	}
	reply, raw := c.rpc(`<get><filter type="subtree"><interfaces xmlns="` + nsIETFInterfaces + `"/></filter></get>`)
	mustNoRPCError(t, reply, raw)
	if got := len(interfacesIn(reply.Child(nsNetconfBase, "data"))); got != 2 {
		t.Fatalf("%d interfaces over Call Home: %s", got, raw)
	}
	st := mgr.GetNetconfStatus()
	if st.CallHome != col.addr() || st.CallHomeConnected == nil || *st.CallHomeConnected != 1 || st.SessionsActive != 1 {
		t.Fatalf("status while connected: %+v", st)
	}
	if len(st.ConfiguredSubscriptions) != 0 {
		t.Errorf("configured subscriptions without any configured: %v", st.ConfiguredSubscriptions)
	}

	// The client ends the session; the device calls again.
	reply, raw = c.rpc(`<close-session/>`)
	mustNoRPCError(t, reply, raw)
	c2 := col.session(t, &pki.client)
	if a, b := childText(c.hello, nsNetconfBase, "session-id"), childText(c2.hello, nsNetconfBase, "session-id"); a == b {
		t.Fatalf("redialled session reuses session-id %s", a)
	}
	st = mgr.GetNetconfStatus()
	if *st.CallHomeSessionsTotal < 1 || *st.CallHomeDials < 2 {
		t.Fatalf("status after the redial: %+v", st)
	}
}

// TestNetconfCallHomeRequiresAClientCertificate: Call Home changes who
// connects, not who authenticates. A client without a certificate fails
// the handshake (RFC 7589 is mutual TLS) and the device keeps calling.
func TestNetconfCallHomeRequiresAClientCertificate(t *testing.T) {
	pki := newTestPKI(t, "callhome-client")
	col := newTestCallHomeCollector(t)
	mgr, _, _ := startTestNetconf(t, 1, NetconfSubsystemConfig{CallHome: col.addr()})

	raw := col.accept(t, 5*time.Second)
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test server's self-signed cert
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a session ran without a client certificate")
	}
	col.session(t, &pki.client) // the device called again
	if got := mgr.GetNetconfStatus().TLSHandshakeFailures; got != 1 {
		t.Fatalf("tls_handshake_failures %d, want 1", got)
	}
}

// TestNetconfCallHomeStopIsPrompt: stopping a device ends its Call Home
// loop wherever it is: in a handshake the client never starts, or in the
// backoff after a refused dial.
func TestNetconfCallHomeStopIsPrompt(t *testing.T) {
	t.Run("handshake", func(t *testing.T) {
		col := newTestCallHomeCollector(t)
		_, dev, _ := startTestNetconf(t, 1, NetconfSubsystemConfig{CallHome: col.addr()})
		raw := col.accept(t, 5*time.Second) // and never speak TLS
		stopTestNetconfDevice(t, dev)
		if got := manager.netconf.tlsHandshakeFailures.Load(); got != 0 {
			t.Errorf("a handshake cut short by the device stopping counted as %d tls_handshake_failures", got)
		}
		_ = raw.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := raw.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Fatalf("the device did not close its Call Home connection: %v", err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close() // nothing listens: every dial is refused
		mgr, dev, _ := startTestNetconf(t, 1, NetconfSubsystemConfig{CallHome: addr})
		deadline := time.Now().Add(5 * time.Second)
		for mgr.netconf.callHomeDialFailures.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if mgr.netconf.callHomeDialFailures.Load() == 0 {
			t.Fatal("no dial failure counted")
		}
		stopTestNetconfDevice(t, dev)
	})
}

func isTimeout(err error) bool {
	var ne net.Error
	return asNetError(err, &ne) && ne.Timeout()
}

// stopTestNetconfDevice stops the device's server and fails if that waits
// for a timeout rather than for its goroutines.
func stopTestNetconfDevice(t *testing.T, dev *DeviceSimulator) {
	t.Helper()
	srv := dev.netconfServer
	start := time.Now()
	dev.mu.Lock()
	dev.stopNetconfServer()
	dev.mu.Unlock()
	if d := time.Since(start); d >= netconfStopTimeout {
		t.Fatalf("stopping the device took %s: its Call Home loop did not end", d)
	}
	done := make(chan struct{})
	go func() { srv.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("NETCONF goroutines still running after stop")
	}
}

// configuredStarted collects the first message of each subscription id
// until every id in want has spoken, and returns them by id.
func configuredStarted(t *testing.T, c *ncTestClient, want ...string) map[string]*xmlElem {
	t.Helper()
	first := map[string]*xmlElem{}
	deadline := time.Now().Add(5 * time.Second)
	for len(first) < len(want) {
		if time.Now().After(deadline) {
			t.Fatalf("subscriptions that spoke: %v, want %v", first, want)
		}
		n, raw := c.notification(5 * time.Second)
		if len(n.Children) != 2 {
			t.Fatalf("notification with %d children: %s", len(n.Children), raw)
		}
		body := n.Children[1]
		id := childText(body, body.Space, "id")
		if id == "" {
			// A stream record carries no id: its subscription must already
			// have been announced.
			if first["1"] == nil {
				t.Fatalf("stream record before subscription-started: %s", raw)
			}
			continue
		}
		if first[id] == nil {
			first[id] = body
		}
	}
	return first
}

// TestNetconfCallHomeDeliversConfiguredSubscriptions: each configured
// subscription opens with subscription-started, then delivers as the
// dynamic kind it mirrors would, under its configured id.
func TestNetconfCallHomeDeliversConfiguredSubscriptions(t *testing.T) {
	pki := newTestPKI(t, "callhome-client")
	col := newTestCallHomeCollector(t)
	mgr, dev, listener := startTestNetconfWith(t, 2, NetconfSubsystemConfig{
		CallHome: col.addr(), CallHomeSubscriptions: "stream,on-change,periodic=1s",
	}, func(d *DeviceSimulator) {
		st := d.metricsCycler.ifCounters.Load().State()
		st.SetLinkState(1, OperUp)
		st.SetLinkState(2, OperUp)
	})
	c := col.session(t, &pki.client)
	first := configuredStarted(t, c, "1", "2", "3")
	for id, wantTarget := range map[string]string{"1": "stream", "2": "on-change", "3": "periodic"} {
		started := first[id]
		if started.Local != "subscription-started" || started.Space != nsSubscribedNotif {
			t.Fatalf("subscription %s opened with <%s>, not subscription-started", id, started.Local)
		}
		switch wantTarget {
		case "stream":
			if childText(started, nsSubscribedNotif, "stream") != netconfStreamName {
				t.Errorf("subscription 1 does not name the NETCONF stream")
			}
		default:
			if started.Child(nsYangPush, "datastore") == nil || started.Child(nsYangPush, wantTarget) == nil {
				t.Errorf("subscription %s lacks its datastore or its %s trigger", id, wantTarget)
			}
		}
		if got := childText(started, nsSubscribedNotif, "encoding"); got != "sn:encode-xml" {
			t.Errorf("subscription %s encoding %q", id, got)
		}
	}
	if got := childText(first["3"], nsYangPush, "periodic", "period"); got != "100" {
		t.Errorf("period %q centiseconds, want 100", got)
	}

	// A link change reaches both the stream and the on-change subscription.
	setLink(t, dev, 1, OperDown)
	var alarm, change bool
	deadline := time.Now().Add(5 * time.Second)
	for !(alarm && change) && time.Now().Before(deadline) {
		n, _ := c.notification(5 * time.Second)
		body := n.Children[1]
		switch {
		case body.Local == "alarm-notification":
			alarm = true
		case body.Local == "push-change-update" && childText(body, nsYangPush, "id") == "2":
			change = true
		}
	}
	if !alarm || !change {
		t.Fatalf("after a link change: alarm %v, push-change-update %v", alarm, change)
	}

	// Configured subscriptions are configuration's to remove, not an RPC's.
	reply, raw := c.rpc(`<delete-subscription xmlns="` + nsSubscribedNotif + `"><id>1</id></delete-subscription>`)
	mustRPCError(t, reply, raw, "invalid-value", "ietf-subscribed-notifications:no-such-subscription")
	// A dynamic subscription on the same session gets an id outside theirs.
	reply, raw = c.rpc(fmt.Sprintf(establishStream, "", ""))
	mustNoRPCError(t, reply, raw)
	if id, _ := strconv.Atoi(childText(reply, nsSubscribedNotif, "id")); id < netconfFirstDynamicSubscriptionID {
		t.Fatalf("dynamic subscription id %d collides with the configured range: %s", id, raw)
	}

	subs := getSubscriptions(t, c)
	if len(subs) != 3 {
		t.Fatalf("/subscriptions lists %d, want the 3 configured", len(subs))
	}
	for id, e := range subs {
		recv := e.Child(nsSubscribedNotif, "receivers").Child(nsSubscribedNotif, "receiver")
		if childText(recv, nsSubscribedNotif, "state") != "active" || childText(e, nsSubscribedNotif, "configured-subscription-state") != "valid" {
			t.Errorf("subscription %s: receiver %q, state %q", id, childText(recv, nsSubscribedNotif, "state"),
				childText(e, nsSubscribedNotif, "configured-subscription-state"))
		}
		if n, _ := strconv.Atoi(childText(recv, nsSubscribedNotif, "sent-event-records")); n < 1 {
			t.Errorf("subscription %s: sent-event-records %d after delivering", id, n)
		}
	}
	if got := mgr.GetNetconfStatus().ConfiguredSubscriptions; strings.Join(got, ",") != "stream,on-change,periodic=1s" {
		t.Errorf("status configured_subscriptions %v", got)
	}

	// Between sessions the receiver is connecting, and the next session
	// opens with subscription-started again. The device's next connection
	// is held in its handshake until col.session, so the state between is
	// observable over the listener.
	other := mustDialTestNetconf(t, listener, &pki.client)
	_ = c.conn.Close()
	deadline = time.Now().Add(5 * time.Second)
	for {
		recv := getSubscriptions(t, other)["1"].Child(nsSubscribedNotif, "receivers").Child(nsSubscribedNotif, "receiver")
		if childText(recv, nsSubscribedNotif, "state") == "connecting" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the receiver stayed active after its session ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
	c2 := col.session(t, &pki.client)
	configuredStarted(t, c2, "1", "2", "3")
}

// TestNetconfConfiguredReceiverIsConnectingWithoutASession reads
// /subscriptions over the listener while no Call Home session is up.
func TestNetconfConfiguredReceiverIsConnectingWithoutASession(t *testing.T) {
	pki := newTestPKI(t, "collector")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, _, listener := startTestNetconf(t, 1, NetconfSubsystemConfig{CallHome: addr, CallHomeSubscriptions: "stream"})
	c := mustDialTestNetconf(t, listener, &pki.client)
	subs := getSubscriptions(t, c)
	recv := subs["1"].Child(nsSubscribedNotif, "receivers").Child(nsSubscribedNotif, "receiver")
	if got := childText(recv, nsSubscribedNotif, "state"); got != "connecting" {
		t.Fatalf("receiver state %q with no Call Home session, want connecting", got)
	}
	// A listener session is not the receiver: it is sent nothing unasked.
	c.expectNoMessage(300 * time.Millisecond)
}

func getSubscriptions(t *testing.T, c *ncTestClient) map[string]*xmlElem {
	t.Helper()
	reply, raw := c.rpc(`<get><filter type="subtree"><subscriptions xmlns="` + nsSubscribedNotif + `"/></filter></get>`)
	mustNoRPCError(t, reply, raw)
	out := map[string]*xmlElem{}
	subs := reply.Child(nsNetconfBase, "data").Child(nsSubscribedNotif, "subscriptions")
	if subs == nil {
		t.Fatalf("no /subscriptions: %s", raw)
	}
	for _, e := range subs.Children {
		out[childText(e, nsSubscribedNotif, "id")] = e
	}
	return out
}

// TestNetconfStatusFingerprintsAreThePresentedCertificate checks both
// fingerprint forms against the certificate a client actually receives.
// The base64 form is what OpenNMS's Call Home listener compares exactly in
// allowedFingerprints, so a colon-hex value pasted there matches nothing.
func TestNetconfStatusFingerprintsAreThePresentedCertificate(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)
	sum := sha256.Sum256(c.conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw)
	st := mgr.GetNetconfStatus()
	if want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]); st.ServerCertFingerprint != want {
		t.Errorf("server_cert_fingerprint %q, want %q", st.ServerCertFingerprint, want)
	}
	if want := strings.ToUpper(fmt.Sprintf("%x", sum[:])); strings.ReplaceAll(st.ServerCertSHA256, ":", "") != want {
		t.Errorf("server_cert_sha256 %q, want the colon form of %s", st.ServerCertSHA256, want)
	}
}
