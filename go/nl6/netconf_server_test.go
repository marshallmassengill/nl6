/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Every test here drives the real server: startNetconfServer's listener,
// the TLS handshake, RFC 6242 framing and the dispatcher, over a socket.

const establishOnChange = `<establish-subscription xmlns="` + nsSubscribedNotif + `" xmlns:yp="` + nsYangPush +
	`" xmlns:ds="` + nsDatastores + `"><yp:datastore>ds:operational</yp:datastore>%s<yp:on-change>%s</yp:on-change></establish-subscription>`

const establishPeriodic = `<establish-subscription xmlns="` + nsSubscribedNotif + `" xmlns:yp="` + nsYangPush +
	`" xmlns:ds="` + nsDatastores + `"><yp:datastore>ds:operational</yp:datastore>%s<yp:periodic><yp:period>%d</yp:period></yp:periodic></establish-subscription>`

func netconfState(t *testing.T, dev *DeviceSimulator) *InterfaceState {
	t.Helper()
	st := dev.metricsCycler.ifCounters.Load().State()
	if st == nil {
		t.Fatal("test device has no state engine")
	}
	return st
}

func setLink(t *testing.T, dev *DeviceSimulator, ifIndex int, link uint8) {
	t.Helper()
	st := netconfState(t, dev)
	if res, evts := st.SetLinkState(ifIndex, link); res == LinkMovedVisible {
		for _, e := range evts {
			st.Broadcast(e)
		}
	}
}

func setAdmin(t *testing.T, dev *DeviceSimulator, ifIndex int, admin uint8) {
	t.Helper()
	st := netconfState(t, dev)
	for _, e := range st.ApplyAdminStatus(ifIndex, admin) {
		st.Broadcast(e)
	}
}

func listenerCount(st *InterfaceState) int {
	n := 0
	st.listeners.Range(func(_, _ any) bool { n++; return true })
	return n
}

func TestNetconfHelloAdvertisesYangLibraryAndChunks(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 2, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)

	var caps []string
	for _, cp := range c.hello.Child(nsNetconfBase, "capabilities").Children {
		caps = append(caps, cp.Text)
	}
	joined := strings.Join(caps, "\n")
	for _, want := range []string{"urn:ietf:params:netconf:base:1.1", "urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&content-id="} {
		if !strings.Contains(joined, want) {
			t.Errorf("hello lacks %q:\n%s", want, joined)
		}
	}
	if childText(c.hello, nsNetconfBase, "session-id") == "" {
		t.Error("hello carries no session-id")
	}
	// The reply would be unreadable here if the server had not switched to
	// chunked framing, since the client reads chunked from now on.
	reply, raw := c.rpc(`<get><filter type="subtree"><yang-library xmlns="` + nsYangLibrary + `"/></filter></get>`)
	mustNoRPCError(t, reply, raw)
	// What OpenNMS's auto mode reads to choose RFC 8639.
	if !containsAll(raw, "<name>ietf-subscribed-notifications</name>", "<name>ietf-yang-push</name>", "<feature>on-change</feature>") {
		t.Errorf("yang-library lacks the subscription modules:\n%s", raw)
	}
}

func TestNetconfBase10ClientStaysOnEndOfMessageFraming(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	c, err := dialTestNetconf(t, addr, &pki.client, false)
	if err != nil {
		t.Fatal(err)
	}
	reply, raw := c.rpc(`<get/>`)
	mustNoRPCError(t, reply, raw)
}

func TestNetconfRequiresClientCertificate(t *testing.T) {
	mgr, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	if _, err := dialTestNetconf(t, addr, nil, true); err == nil {
		t.Fatal("a client without a certificate completed a session")
	}
	waitForAtomic(t, func() uint64 { return mgr.netconf.tlsHandshakeFailures.Load() }, 1)
	if got := mgr.GetNetconfStatus().ClientAuth; got != netconfClientAuthAny {
		t.Errorf("client_auth %q, want %q", got, netconfClientAuthAny)
	}
}

func TestNetconfVerifiesClientCertificateAgainstCA(t *testing.T) {
	trusted := newTestPKI(t, "trusted")
	other := newTestPKI(t, "other")
	mgr, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{ClientCAPEM: trusted.caPEM})
	// Positive control on the same listener: a refusal below is then a
	// verdict about the certificate, not a dead socket.
	c := mustDialTestNetconf(t, addr, &trusted.client)
	reply, raw := c.rpc(`<get/>`)
	mustNoRPCError(t, reply, raw)
	if _, err := dialTestNetconf(t, addr, &other.client, true); err == nil {
		t.Fatal("a certificate from an untrusted CA completed a session")
	}
	waitForAtomic(t, func() uint64 { return mgr.netconf.tlsHandshakeFailures.Load() }, 1)
	if got := mgr.GetNetconfStatus().ClientAuth; got != netconfClientAuthVerified {
		t.Errorf("client_auth %q, want %q", got, netconfClientAuthVerified)
	}
}

func waitForAtomic(t *testing.T, read func() uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for read() < want {
		if time.Now().After(deadline) {
			t.Fatalf("counter %d, want %d", read(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNetconfGetDataServesInterfacesFromTheStateEngine(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, dev, addr := startTestNetconf(t, 3, NetconfSubsystemConfig{})
	setLink(t, dev, 1, OperUp)
	setLink(t, dev, 2, OperDown)
	setAdmin(t, dev, 3, AdminDown)
	c := mustDialTestNetconf(t, addr, &pki.client)

	reply, raw := c.rpc(`<get-data xmlns="` + nsNetconfNMDA + `" xmlns:ds="` + nsDatastores + `"><datastore>ds:operational</datastore></get-data>`)
	mustNoRPCError(t, reply, raw)
	ifs := interfacesIn(reply.Child(nsNetconfNMDA, "data"))
	if len(ifs) != 3 {
		t.Fatalf("got %d interfaces, want 3: %s", len(ifs), raw)
	}
	for name, want := range map[string][2]string{"TestIf1": {"up", "up"}, "TestIf2": {"up", "down"}, "TestIf3": {"down", "down"}} {
		e := ifs[name]
		if got := childText(e, nsIETFInterfaces, "admin-status"); got != want[0] {
			t.Errorf("%s admin-status %q, want %q", name, got, want[0])
		}
		if got := childText(e, nsIETFInterfaces, "oper-status"); got != want[1] {
			t.Errorf("%s oper-status %q, want %q", name, got, want[1])
		}
	}
	e := ifs["TestIf1"]
	if got := childText(e, nsIETFInterfaces, "type"); got != "ianaift:ethernetCsmacd" {
		t.Errorf("type %q", got)
	}
	if got := childText(e, nsIETFInterfaces, "if-index"); got != "1" {
		t.Errorf("if-index %q", got)
	}
	if got := childText(e, nsIETFInterfaces, "statistics", "in-octets"); got == "" {
		t.Errorf("no statistics/in-octets: %s", raw)
	}
	if got := childText(ifs["TestIf3"], nsIETFInterfaces, "enabled"); got != "false" {
		t.Errorf("admin-down interface enabled=%q, want false", got)
	}
}

func TestNetconfFiltersSelectTheSameDataBothWays(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 3, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)

	xp, xraw := c.rpc(`<get-data xmlns="` + nsNetconfNMDA + `" xmlns:ds="` + nsDatastores + `"><datastore>ds:operational</datastore>` +
		`<xpath-filter xmlns:if="` + nsIETFInterfaces + `">/if:interfaces/if:interface[if:name='TestIf2']/if:oper-status</xpath-filter></get-data>`)
	mustNoRPCError(t, xp, xraw)
	st, sraw := c.rpc(`<get-data xmlns="` + nsNetconfNMDA + `" xmlns:ds="` + nsDatastores + `"><datastore>ds:operational</datastore>` +
		`<subtree-filter><interfaces xmlns="` + nsIETFInterfaces + `"><interface><name>TestIf2</name><oper-status/></interface></interfaces></subtree-filter></get-data>`)
	mustNoRPCError(t, st, sraw)
	dataOf := func(raw string) string { return raw[strings.Index(raw, "<data"):] }
	if dataOf(xraw) != dataOf(sraw) {
		t.Fatalf("xpath and subtree filters disagree:\n%s\n%s", xraw, sraw)
	}
	ifs := interfacesIn(xp.Child(nsNetconfNMDA, "data"))
	if len(ifs) != 1 || ifs["TestIf2"] == nil || len(ifs["TestIf2"].Children) != 2 {
		t.Fatalf("filter selected the wrong data: %s", xraw)
	}
	// A module name works as a prefix without a declaration, as OpenNMS writes it.
	mod, mraw := c.rpc(`<get-data xmlns="` + nsNetconfNMDA + `" xmlns:ds="` + nsDatastores + `"><datastore>ds:operational</datastore>` +
		`<xpath-filter>/ietf-interfaces:interfaces/ietf-interfaces:interface[ietf-interfaces:name='TestIf2']/ietf-interfaces:oper-status</xpath-filter></get-data>`)
	mustNoRPCError(t, mod, mraw)
	if dataOf(mraw) != dataOf(sraw) {
		t.Fatalf("module-name prefixes select differently:\n%s", mraw)
	}
	bad, braw := c.rpc(`<get-data xmlns="` + nsNetconfNMDA + `" xmlns:ds="` + nsDatastores + `"><datastore>ds:operational</datastore>` +
		`<xpath-filter>//interface</xpath-filter></get-data>`)
	mustRPCError(t, bad, braw, "invalid-value", "")
}

func TestNetconfGetDataConfigFilter(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)
	get := func(mode string) (*xmlElem, string) {
		reply, raw := c.rpc(`<get-data xmlns="` + nsNetconfNMDA + `" xmlns:ds="` + nsDatastores + `"><datastore>ds:operational</datastore>` +
			`<config-filter>` + mode + `</config-filter></get-data>`)
		mustNoRPCError(t, reply, raw)
		return reply.Child(nsNetconfNMDA, "data"), raw
	}
	data, raw := get("false")
	e := interfacesIn(data)["TestIf1"]
	if e == nil || e.Child(nsIETFInterfaces, "oper-status") == nil || e.Child(nsIETFInterfaces, "enabled") != nil ||
		e.Child(nsIETFInterfaces, "type") != nil || data.Child(nsYangLibrary, "modules-state") == nil {
		t.Fatalf("config-filter false: want state nodes and the key only:\n%s", raw)
	}
	data, raw = get("true")
	e = interfacesIn(data)["TestIf1"]
	if e == nil || e.Child(nsIETFInterfaces, "enabled") == nil || e.Child(nsIETFInterfaces, "oper-status") != nil ||
		data.Child(nsYangLibrary, "yang-library") != nil {
		t.Fatalf("config-filter true: want config nodes only:\n%s", raw)
	}
}

func TestNetconfGetConfigServesOnlyConfigNodes(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw := c.rpc(`<get-config><source><running/></source></get-config>`)
	mustNoRPCError(t, reply, raw)
	e := interfacesIn(reply.Child(nsNetconfBase, "data"))["TestIf1"]
	if e == nil {
		t.Fatalf("no interface: %s", raw)
	}
	for _, c := range e.Children {
		switch c.Local {
		case "name", "type", "enabled":
		default:
			t.Errorf("running datastore serves state node %s", c.Local)
		}
	}
	if strings.Contains(raw, "yang-library") {
		t.Error("running datastore serves the yang-library state")
	}
	reply, raw = c.rpc(`<get-config><source><candidate/></source></get-config>`)
	mustRPCError(t, reply, raw, "invalid-value", "")
}

func TestNetconfOnChangePushesEditsForStateTransitions(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, dev, addr := startTestNetconf(t, 2, NetconfSubsystemConfig{})
	dev.resources.oidIndex.Store(".1.3.6.1.2.1.2.2.1.2.1", "Gi0/1") // a name that needs percent-encoding
	setLink(t, dev, 1, OperUp)
	c := mustDialTestNetconf(t, addr, &pki.client)

	reply, raw := c.rpc(fmt.Sprintf(establishOnChange, "", ""))
	mustNoRPCError(t, reply, raw)
	id := childText(reply, nsSubscribedNotif, "id")
	if id == "" {
		t.Fatalf("no subscription id: %s", raw)
	}
	// sync-on-start defaults to true: the full selection comes first.
	n, nraw := c.notification(5 * time.Second)
	pu := n.Child(nsYangPush, "push-update")
	if pu == nil || childText(pu, nsYangPush, "id") != id || pu.Child(nsYangPush, "datastore-contents") == nil {
		t.Fatalf("first notification is not the sync push-update: %s", nraw)
	}

	setLink(t, dev, 1, OperDown)
	n, nraw = c.notification(5 * time.Second)
	pcu := n.Child(nsYangPush, "push-change-update")
	if pcu == nil || childText(pcu, nsYangPush, "id") != id {
		t.Fatalf("expected a push-change-update: %s", nraw)
	}
	if !containsAll(nraw, "<operation>replace</operation>",
		"<target>/ietf-interfaces:interfaces/interface=Gi0%2F1/oper-status</target>",
		`<oper-status xmlns="`+nsIETFInterfaces+`">down</oper-status>`,
		"<target>/ietf-interfaces:interfaces/interface=Gi0%2F1/last-change</target>") {
		t.Fatalf("push-change-update edits wrong:\n%s", nraw)
	}
	if strings.Contains(nraw, "admin-status") {
		t.Errorf("an oper move reported admin-status: %s", nraw)
	}

	setAdmin(t, dev, 2, AdminDown)
	_, nraw = c.notification(5 * time.Second)
	if !containsAll(nraw, "interface=TestIf2/admin-status", "interface=TestIf2/enabled",
		`<enabled xmlns="`+nsIETFInterfaces+`">false</enabled>`) {
		t.Fatalf("admin-down edits wrong:\n%s", nraw)
	}
	// The engine reports the derived oper move as its own event, so it
	// arrives as its own update.
	_, nraw = c.notification(5 * time.Second)
	if !containsAll(nraw, "interface=TestIf2/oper-status", ">down</oper-status>") || strings.Contains(nraw, "admin-status") {
		t.Fatalf("derived oper edit wrong:\n%s", nraw)
	}
	if got := mgr.GetNetconfStatus().PushChangeUpdates; got != 3 {
		t.Errorf("push_change_updates %d, want 3", got)
	}
}

func TestNetconfOnChangeHonoursTheFilter(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, dev, addr := startTestNetconf(t, 2, NetconfSubsystemConfig{})
	setLink(t, dev, 1, OperUp)
	setLink(t, dev, 2, OperUp)
	c := mustDialTestNetconf(t, addr, &pki.client)
	filter := `<yp:datastore-xpath-filter xmlns:if="` + nsIETFInterfaces + `">/if:interfaces/if:interface[if:name='TestIf2']/if:oper-status</yp:datastore-xpath-filter>`
	reply, raw := c.rpc(fmt.Sprintf(establishOnChange, filter, "<yp:sync-on-start>false</yp:sync-on-start>"))
	mustNoRPCError(t, reply, raw)

	setLink(t, dev, 1, OperDown)      // not selected: another interface
	setAdmin(t, dev, 2, AdminTesting) // not selected: admin-status; oper follows to testing
	_, nraw := c.notification(5 * time.Second)
	if !containsAll(nraw, "interface=TestIf2/oper-status", ">testing</oper-status>") || strings.Contains(nraw, "TestIf1") ||
		strings.Contains(nraw, "admin-status") || strings.Contains(nraw, "last-change") {
		t.Fatalf("filter not applied to the change:\n%s", nraw)
	}
	c.expectNoMessage(300 * time.Millisecond)
}

func TestNetconfOnChangeDampeningCoalesces(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, dev, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	setLink(t, dev, 1, OperUp)
	c := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw := c.rpc(fmt.Sprintf(establishOnChange, "",
		"<yp:dampening-period>50</yp:dampening-period><yp:sync-on-start>false</yp:sync-on-start>"))
	mustNoRPCError(t, reply, raw)
	setLink(t, dev, 1, OperDown)
	setLink(t, dev, 1, OperUp)
	setLink(t, dev, 1, OperDown)
	_, nraw := c.notification(5 * time.Second)
	if strings.Count(nraw, "<edit>") != 2 || !strings.Contains(nraw, ">down</oper-status>") {
		t.Fatalf("three moves within the dampening period should be one update with the last value:\n%s", nraw)
	}
	c.expectNoMessage(800 * time.Millisecond)
}

func TestNetconfPeriodicPushUpdates(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, _, addr := startTestNetconf(t, 2, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw := c.rpc(fmt.Sprintf(establishPeriodic,
		`<yp:datastore-subtree-filter><interfaces xmlns="`+nsIETFInterfaces+`"><interface><name/><statistics><in-octets/></statistics></interface></interfaces></yp:datastore-subtree-filter>`, 100))
	mustNoRPCError(t, reply, raw)
	var octets []string
	for i := 0; i < 2; i++ {
		n, nraw := c.notification(5 * time.Second)
		pu := n.Child(nsYangPush, "push-update")
		if pu == nil {
			t.Fatalf("expected push-update: %s", nraw)
		}
		ifs := interfacesIn(pu.Child(nsYangPush, "datastore-contents"))
		if len(ifs) != 2 || strings.Contains(nraw, "oper-status") {
			t.Fatalf("filter not applied: %s", nraw)
		}
		octets = append(octets, childText(ifs["TestIf1"], nsIETFInterfaces, "statistics", "in-octets"))
	}
	if octets[0] == "" || octets[0] == octets[1] {
		t.Errorf("in-octets did not advance across a period: %v", octets)
	}
	if got := mgr.GetNetconfStatus().PushUpdates; got < 2 {
		t.Errorf("push_updates %d", got)
	}
}

func TestNetconfEstablishSubscriptionRefusals(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)
	for _, tc := range []struct {
		name, op, tag, appTag string
	}{
		{"period below the floor", fmt.Sprintf(establishPeriodic, "", 50), "invalid-value", "ietf-yang-push:period-unsupported"},
		{"event stream", `<establish-subscription xmlns="` + nsSubscribedNotif + `"><stream>NETCONF</stream></establish-subscription>`,
			"invalid-value", "ietf-subscribed-notifications:stream-unavailable"},
		{"unserved datastore", strings.Replace(fmt.Sprintf(establishOnChange, "", ""), "ds:operational", "ds:candidate", 1),
			"invalid-value", "ietf-yang-push:datastore-not-subscribable"},
		{"json encoding", strings.Replace(fmt.Sprintf(establishOnChange, "", ""), "<yp:on-change>",
			"<encoding>encode-json</encoding><yp:on-change>", 1), "invalid-value", "ietf-subscribed-notifications:encoding-unsupported"},
		{"unsupported xpath", fmt.Sprintf(establishOnChange, "<yp:datastore-xpath-filter>/a/*</yp:datastore-xpath-filter>", ""),
			"invalid-value", "ietf-subscribed-notifications:filter-unsupported"},
		{"no update trigger", `<establish-subscription xmlns="` + nsSubscribedNotif + `" xmlns:yp="` + nsYangPush +
			`" xmlns:ds="` + nsDatastores + `"><yp:datastore>ds:operational</yp:datastore></establish-subscription>`, "missing-element", ""},
		{"stop-time in the past", strings.Replace(fmt.Sprintf(establishOnChange, "", ""), "<yp:on-change>",
			"<stop-time>2001-01-01T00:00:00Z</stop-time><yp:on-change>", 1), "invalid-value", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply, raw := c.rpc(tc.op)
			mustRPCError(t, reply, raw, tc.tag, tc.appTag)
		})
	}
}

func TestNetconfSubscriptionLimitAndDelete(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, dev, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	st := netconfState(t, dev)
	base := listenerCount(st)
	c := mustDialTestNetconf(t, addr, &pki.client)
	var ids []string
	for i := 0; i < netconfMaxSubscriptionsPerSession; i++ {
		reply, raw := c.rpc(fmt.Sprintf(establishOnChange, "", "<yp:sync-on-start>false</yp:sync-on-start>"))
		mustNoRPCError(t, reply, raw)
		ids = append(ids, childText(reply, nsSubscribedNotif, "id"))
	}
	reply, raw := c.rpc(fmt.Sprintf(establishOnChange, "", ""))
	mustRPCError(t, reply, raw, "invalid-value", "ietf-subscribed-notifications:insufficient-resources")
	if got := listenerCount(st) - base; got != netconfMaxSubscriptionsPerSession {
		t.Fatalf("%d state listeners for %d subscriptions", got, netconfMaxSubscriptionsPerSession)
	}

	reply, raw = c.rpc(`<delete-subscription xmlns="` + nsSubscribedNotif + `"><id>` + ids[0] + `</id></delete-subscription>`)
	mustNoRPCError(t, reply, raw)
	reply, raw = c.rpc(`<delete-subscription xmlns="` + nsSubscribedNotif + `"><id>` + ids[0] + `</id></delete-subscription>`)
	mustRPCError(t, reply, raw, "invalid-value", "ietf-subscribed-notifications:no-such-subscription")
	if got := listenerCount(st) - base; got != netconfMaxSubscriptionsPerSession-1 {
		t.Fatalf("delete left %d listeners", got)
	}

	// Closing the session releases every remaining subscription.
	reply, raw = c.rpc(`<close-session/>`)
	mustNoRPCError(t, reply, raw)
	deadline := time.Now().Add(5 * time.Second)
	for listenerCount(st) != base || mgr.netconf.subscriptionsActive.Load() != 0 || mgr.netconf.sessionsActive.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("after close-session: %d listeners (base %d), %d subscriptions, %d sessions",
				listenerCount(st), base, mgr.netconf.subscriptionsActive.Load(), mgr.netconf.sessionsActive.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNetconfStopTimeTerminatesTheSubscription(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)
	stop := time.Now().Add(400 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	reply, raw := c.rpc(strings.Replace(fmt.Sprintf(establishOnChange, "", "<yp:sync-on-start>false</yp:sync-on-start>"),
		"<yp:on-change>", "<stop-time>"+stop+"</stop-time><yp:on-change>", 1))
	mustNoRPCError(t, reply, raw)
	n, nraw := c.notification(5 * time.Second)
	term := n.Child(nsSubscribedNotif, "subscription-terminated")
	if term == nil || childText(term, nsSubscribedNotif, "reason") != "sn:no-such-subscription" ||
		childText(term, nsSubscribedNotif, "id") != childText(reply, nsSubscribedNotif, "id") {
		t.Fatalf("expected subscription-terminated (no-such-subscription) for the subscription: %s", nraw)
	}
	if got := mgr.netconf.subscriptionsActive.Load(); got != 0 {
		t.Errorf("%d subscriptions active after completion", got)
	}
}

func TestNetconfProtocolErrorsAndBaseOperations(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)

	// Malformed XML is answered, and the session survives it.
	c.sendRaw(`<rpc xmlns="` + nsNetconfBase + `" message-id="x"><get></rpc>`)
	el, raw := c.next(5 * time.Second)
	mustRPCError(t, el, raw, "malformed-message", "")

	// Character data ahead of a child element: the input that once
	// panicked the parser, and with it the whole simulator (FuzzNetconfRequest).
	reply0, raw0 := c.rpc(`<get>text<filter type="subtree"/></get>`)
	mustNoRPCError(t, reply0, raw0)

	c.sendRaw(`<rpc xmlns="` + nsNetconfBase + `"><get/></rpc>`)
	el, raw = c.next(5 * time.Second)
	mustRPCError(t, el, raw, "missing-attribute", "")

	// Extra rpc attributes are echoed on the reply (RFC 6241 §4.2).
	c.sendRaw(`<rpc xmlns="` + nsNetconfBase + `" message-id="7" xmlns:ex="urn:example" ex:user-id="fred"><get/></rpc>`)
	_, raw = c.next(5 * time.Second)
	if !containsAll(raw, `message-id="7"`, `="urn:example"`, `:user-id="fred"`) {
		t.Errorf("rpc attributes not echoed: %s", raw[:min(len(raw), 300)])
	}

	reply, raw := c.rpc(`<edit-config><target><running/></target></edit-config>`)
	mustRPCError(t, reply, raw, "operation-not-supported", "")
	reply, raw = c.rpc(`<create-subscription xmlns="` + nsNetconfNotif + `"/>`)
	mustRPCError(t, reply, raw, "operation-not-supported", "")

	reply, raw = c.rpc(`<lock><target><running/></target></lock>`)
	mustNoRPCError(t, reply, raw)
	other := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw = other.rpc(`<lock><target><running/></target></lock>`)
	mustRPCError(t, reply, raw, "lock-denied", "")
	if !strings.Contains(raw, "<session-id>"+childText(c.hello, nsNetconfBase, "session-id")+"</session-id>") {
		t.Errorf("lock-denied does not name the holder: %s", raw)
	}
	// kill-session ends the holder and releases its lock.
	reply, raw = other.rpc(`<kill-session><session-id>` + childText(c.hello, nsNetconfBase, "session-id") + `</session-id></kill-session>`)
	mustNoRPCError(t, reply, raw)
	reply, raw = other.rpc(`<lock><target><running/></target></lock>`)
	mustNoRPCError(t, reply, raw)
	reply, raw = other.rpc(`<unlock><target><running/></target></unlock>`)
	mustNoRPCError(t, reply, raw)
}

func TestNetconfDeviceStopClosesSessions(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, dev, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	st := netconfState(t, dev)
	base := listenerCount(st)
	c := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw := c.rpc(fmt.Sprintf(establishOnChange, "", "<yp:sync-on-start>false</yp:sync-on-start>"))
	mustNoRPCError(t, reply, raw)
	dev.mu.Lock()
	dev.stopNetconfServer()
	dev.mu.Unlock()
	if _, err := c.rd.ReadMessage(); err == nil {
		t.Fatal("session survived the device stopping")
	}
	if listenerCount(st) != base || mgr.netconf.subscriptionsActive.Load() != 0 || mgr.netconf.sessionsActive.Load() != 0 {
		t.Fatalf("device stop leaked: %d listeners (base %d), %d subscriptions, %d sessions",
			listenerCount(st), base, mgr.netconf.subscriptionsActive.Load(), mgr.netconf.sessionsActive.Load())
	}
}

func TestNetconfSessionCapRefusesBeforeHandshake(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	for i := 0; i < netconfMaxSessionsPerDevice; i++ {
		mustDialTestNetconf(t, addr, &pki.client)
	}
	if _, err := dialTestNetconf(t, addr, &pki.client, true); err == nil {
		t.Fatal("a session over the per-device cap was served")
	}
	waitForAtomic(t, func() uint64 { return mgr.netconf.sessionsRefused.Load() }, 1)
}

func TestNetconfSubsystemConfigValidation(t *testing.T) {
	pki := newTestPKI(t, "x")
	for _, tc := range []struct {
		name string
		cfg  NetconfSubsystemConfig
	}{
		{"cert without key", NetconfSubsystemConfig{Enabled: true, CertPEM: pki.caPEM}},
		{"CA bundle without certificates", NetconfSubsystemConfig{Enabled: true, ClientCAPEM: []byte("not pem")}},
		{"port out of range", NetconfSubsystemConfig{Enabled: true, Port: 70000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := &SimulatorManager{sharedTLSCert: &tls.Certificate{}}
			if err := mgr.StartNetconfSubsystem(tc.cfg); err == nil {
				t.Fatal("accepted")
			}
			if mgr.netconf.active.Load() {
				t.Fatal("subsystem active after a refused start")
			}
		})
	}
	mgr := &SimulatorManager{}
	if err := mgr.StartNetconfSubsystem(NetconfSubsystemConfig{}); err != nil || mgr.netconf.active.Load() {
		t.Fatalf("disabled config: err=%v active=%v", err, mgr.netconf.active.Load())
	}
}
