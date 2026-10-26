/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const establishStream = `<establish-subscription xmlns="` + nsSubscribedNotif + `">%s<stream>NETCONF</stream>%s</establish-subscription>`

const alarmXPathFilter = `<stream-xpath-filter>/ietf-alarms:alarm-notification</stream-xpath-filter>`

func alarmIn(t *testing.T, n *xmlElem, raw string) (severity, text string) {
	t.Helper()
	a := n.Child(nsAlarms, "alarm-notification")
	if a == nil {
		t.Fatalf("expected alarm-notification: %s", raw)
	}
	if got := childText(a, nsAlarms, "alarm-type-id"); got != "nl6-at:link-down" {
		t.Fatalf("alarm-type-id %q: %s", got, raw)
	}
	return childText(a, nsAlarms, "perceived-severity"), childText(a, nsAlarms, "alarm-text")
}

func TestNetconfStreamCarriesLinkAlarms(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, dev, addr := startTestNetconfWith(t, 2, NetconfSubsystemConfig{}, func(d *DeviceSimulator) {
		st := d.metricsCycler.ifCounters.Load().State()
		st.SetLinkState(1, OperUp)
		st.SetLinkState(2, OperUp)
	})
	c := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw := c.rpc(fmt.Sprintf(establishStream, alarmXPathFilter, ""))
	mustNoRPCError(t, reply, raw)

	setLink(t, dev, 1, OperDown)
	n, raw := c.notification(5 * time.Second)
	if sev, text := alarmIn(t, n, raw); sev != "major" || text != "Interface TestIf1 is down" {
		t.Fatalf("raise: severity %q text %q", sev, text)
	}
	res := n.Child(nsAlarms, "alarm-notification").Child(nsAlarms, "resource")
	if res.Text != "/if:interfaces/if:interface[if:name='TestIf1']" || res.Scope["if"] != nsIETFInterfaces {
		t.Errorf("resource is not the interface's instance-identifier: %s", raw)
	}
	// An admin shutdown is deliberate: the alarm clears though the link is
	// still down, and unshutting the port raises it again.
	setAdmin(t, dev, 1, AdminDown)
	n, raw = c.notification(5 * time.Second)
	if sev, _ := alarmIn(t, n, raw); sev != "cleared" {
		t.Fatalf("admin down: severity %q, want cleared", sev)
	}
	setAdmin(t, dev, 1, AdminUp)
	n, raw = c.notification(5 * time.Second)
	if sev, _ := alarmIn(t, n, raw); sev != "major" {
		t.Fatalf("admin up over a down link: severity %q, want major", sev)
	}
	setLink(t, dev, 1, OperUp)
	n, raw = c.notification(5 * time.Second)
	if sev, text := alarmIn(t, n, raw); sev != "cleared" || text != "Interface TestIf1 is up" {
		t.Fatalf("clear: severity %q text %q", sev, text)
	}
	if got := mgr.GetNetconfStatus().EventNotifications; got != 4 {
		t.Errorf("event_notifications %d, want 4", got)
	}
}

func TestNetconfAlarmListKeepsClearedAlarmsAndSeedsFromStartState(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, dev, addr := startTestNetconfWith(t, 3, NetconfSubsystemConfig{}, func(d *DeviceSimulator) {
		st := d.metricsCycler.ifCounters.Load().State()
		st.SetLinkState(1, OperUp)
		st.SetLinkState(2, OperDown) // down before the server starts
		st.SetLinkState(3, OperUp)
	})
	c := mustDialTestNetconf(t, addr, &pki.client)
	alarms := func() map[string]*xmlElem {
		reply, raw := c.rpc(`<get><filter type="subtree"><alarms xmlns="` + nsAlarms + `"><alarm-list/></alarms></filter></get>`)
		mustNoRPCError(t, reply, raw)
		out := map[string]*xmlElem{}
		list := reply.Child(nsNetconfBase, "data").Child(nsAlarms, "alarms").Child(nsAlarms, "alarm-list")
		for _, a := range list.Children {
			if a.Local == "alarm" {
				out[childText(a, nsAlarms, "alarm-text")[len("Interface "):][:7]] = a
			}
		}
		if got := childText(list, nsAlarms, "number-of-alarms"); got != fmt.Sprint(len(out)) {
			t.Fatalf("number-of-alarms %s for %d entries: %s", got, len(out), raw)
		}
		return out
	}
	got := alarms()
	if len(got) != 1 || childText(got["TestIf2"], nsAlarms, "is-cleared") != "false" {
		t.Fatalf("seeded alarm list: %v", got)
	}
	setLink(t, dev, 3, OperDown)
	setLink(t, dev, 3, OperUp)
	got = alarms()
	if len(got) != 2 || childText(got["TestIf3"], nsAlarms, "is-cleared") != "true" ||
		childText(got["TestIf3"], nsAlarms, "perceived-severity") != "major" {
		t.Fatalf("a cleared alarm must stay listed with is-cleared true and its last severity: %v", got)
	}
	created := childText(got["TestIf3"], nsAlarms, "time-created")
	setLink(t, dev, 3, OperDown)
	got = alarms()
	if childText(got["TestIf3"], nsAlarms, "is-cleared") != "false" || childText(got["TestIf3"], nsAlarms, "time-created") != created ||
		childText(got["TestIf3"], nsAlarms, "last-raised") == created {
		t.Fatalf("a re-raised alarm keeps time-created and moves last-raised: %v", got["TestIf3"])
	}
}

func TestNetconfRFC5277CreateSubscription(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, dev, addr := startTestNetconfWith(t, 1, NetconfSubsystemConfig{}, func(d *DeviceSimulator) {
		d.metricsCycler.ifCounters.Load().State().SetLinkState(1, OperUp)
	})
	c := mustDialTestNetconf(t, addr, &pki.client)
	advertised := false
	for _, cp := range c.hello.Child(nsNetconfBase, "capabilities").Children {
		advertised = advertised || cp.Text == "urn:ietf:params:netconf:capability:notification:1.0"
	}
	if !advertised {
		t.Fatal("the hello does not advertise :notification:1.0")
	}
	reply, raw := c.rpc(`<create-subscription xmlns="` + nsNetconfNotif + `"><stream>NETCONF</stream>` +
		`<filter type="subtree"><alarm-notification xmlns="` + nsAlarms + `"/></filter></create-subscription>`)
	mustNoRPCError(t, reply, raw)
	reply, raw = c.rpc(`<create-subscription xmlns="` + nsNetconfNotif + `"/>`)
	mustRPCError(t, reply, raw, "operation-failed", "")
	setLink(t, dev, 1, OperDown)
	n, raw := c.notification(5 * time.Second)
	if sev, _ := alarmIn(t, n, raw); sev != "major" {
		t.Fatalf("severity %q", sev)
	}
	for _, bad := range []struct{ op, tag string }{
		{`<create-subscription xmlns="` + nsNetconfNotif + `"><stream>SYSLOG</stream></create-subscription>`, "invalid-value"},
		{`<create-subscription xmlns="` + nsNetconfNotif + `"><stopTime>2001-01-01T00:00:00Z</stopTime></create-subscription>`, "missing-element"},
		{`<create-subscription xmlns="` + nsNetconfNotif + `"><startTime>2999-01-01T00:00:00Z</startTime></create-subscription>`, "bad-element"},
	} {
		other := mustDialTestNetconf(t, addr, &pki.client)
		reply, raw = other.rpc(bad.op)
		mustRPCError(t, reply, raw, bad.tag, "")
	}
}

func TestNetconfStreamReplay(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, dev, addr := startTestNetconfWith(t, 1, NetconfSubsystemConfig{}, func(d *DeviceSimulator) {
		d.metricsCycler.ifCounters.Load().State().SetLinkState(1, OperUp)
	})
	before := time.Now().Add(-time.Hour)
	setLink(t, dev, 1, OperDown) // recorded with nobody subscribed
	setLink(t, dev, 1, OperUp)

	// RFC 8639: a start time older than the buffer is revised, and the
	// reply carries the revision.
	c := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw := c.rpc(fmt.Sprintf(establishStream, alarmXPathFilter,
		"<replay-start-time>"+netconfDateTime(before)+"</replay-start-time>"))
	mustNoRPCError(t, reply, raw)
	if childText(reply, nsSubscribedNotif, "replay-start-time-revision") == "" {
		t.Errorf("no replay-start-time-revision for a start before the log: %s", raw)
	}
	for _, want := range []string{"major", "cleared"} {
		n, nraw := c.notification(5 * time.Second)
		if sev, _ := alarmIn(t, n, nraw); sev != want {
			t.Fatalf("replayed severity %q, want %q", sev, want)
		}
	}
	n, nraw := c.notification(5 * time.Second)
	if done := n.Child(nsSubscribedNotif, "replay-completed"); done == nil ||
		childText(done, nsSubscribedNotif, "id") != childText(reply, nsSubscribedNotif, "id") {
		t.Fatalf("expected replay-completed: %s", nraw)
	}
	setLink(t, dev, 1, OperDown) // live after replay
	n, nraw = c.notification(5 * time.Second)
	if sev, _ := alarmIn(t, n, nraw); sev != "major" {
		t.Fatalf("live after replay: %q", sev)
	}

	// RFC 5277: replay, replayComplete, and notificationComplete at stopTime.
	c5 := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw = c5.rpc(`<create-subscription xmlns="` + nsNetconfNotif + `"><filter type="subtree"><alarm-notification xmlns="` + nsAlarms + `"/></filter>` +
		`<startTime>` + netconfDateTime(before) + `</startTime><stopTime>` + netconfDateTime(time.Now().Add(300*time.Millisecond)) + `</stopTime></create-subscription>`)
	mustNoRPCError(t, reply, raw)
	for i := 0; i < 3; i++ {
		n, nraw = c5.notification(5 * time.Second)
		alarmIn(t, n, nraw)
	}
	if n, nraw = c5.notification(5 * time.Second); n.Child(nsNetmodNotification, "replayComplete") == nil {
		t.Fatalf("expected replayComplete: %s", nraw)
	}
	if n, nraw = c5.notification(5 * time.Second); n.Child(nsNetmodNotification, "notificationComplete") == nil {
		t.Fatalf("expected notificationComplete: %s", nraw)
	}
	// The session can subscribe again once the first one completed.
	reply, raw = c5.rpc(`<create-subscription xmlns="` + nsNetconfNotif + `"/>`)
	mustNoRPCError(t, reply, raw)
}

func TestNetconfSessionEventsOnTheStream(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	watcher := mustDialTestNetconf(t, addr, &pki.client)
	reply, raw := watcher.rpc(fmt.Sprintf(establishStream,
		`<stream-subtree-filter><netconf-session-start xmlns="`+nsNetconfNotifications+`"/><netconf-session-end xmlns="`+nsNetconfNotifications+`"/></stream-subtree-filter>`, ""))
	mustNoRPCError(t, reply, raw)

	b := mustDialTestNetconf(t, addr, &pki.client)
	bid := childText(b.hello, nsNetconfBase, "session-id")
	n, nraw := watcher.notification(5 * time.Second)
	start := n.Child(nsNetconfNotifications, "netconf-session-start")
	if start == nil || childText(start, nsNetconfNotifications, "session-id") != bid ||
		childText(start, nsNetconfNotifications, "username") != "collector" ||
		childText(start, nsNetconfNotifications, "source-host") != "127.0.0.1" {
		t.Fatalf("session-start: %s", nraw)
	}
	reply, raw = b.rpc(`<close-session/>`)
	mustNoRPCError(t, reply, raw)
	n, nraw = watcher.notification(5 * time.Second)
	if end := n.Child(nsNetconfNotifications, "netconf-session-end"); end == nil ||
		childText(end, nsNetconfNotifications, "termination-reason") != "closed" {
		t.Fatalf("session-end after close-session: %s", nraw)
	}

	k := mustDialTestNetconf(t, addr, &pki.client)
	kid := childText(k.hello, nsNetconfBase, "session-id")
	watcher.notification(5 * time.Second) // its session-start
	reply, raw = watcher.rpc(`<kill-session><session-id>` + kid + `</session-id></kill-session>`)
	mustNoRPCError(t, reply, raw)
	n, nraw = watcher.notification(5 * time.Second)
	end := n.Child(nsNetconfNotifications, "netconf-session-end")
	if end == nil || childText(end, nsNetconfNotifications, "termination-reason") != "killed" ||
		childText(end, nsNetconfNotifications, "killed-by") != childText(watcher.hello, nsNetconfBase, "session-id") {
		t.Fatalf("session-end after kill-session: %s", nraw)
	}
}

func TestNetconfGetSchemaServesEveryLibraryModule(t *testing.T) {
	pki := newTestPKI(t, "collector")
	_, _, addr := startTestNetconf(t, 1, NetconfSubsystemConfig{})
	c := mustDialTestNetconf(t, addr, &pki.client)
	for _, m := range netconfModules {
		reply, raw := c.rpc(`<get-schema xmlns="` + nsNetconfMonitoring + `"><identifier>` + m.Name + `</identifier><version>` + m.Revision +
			`</version><format>yang</format></get-schema>`)
		mustNoRPCError(t, reply, raw)
		text := childText(reply, nsNetconfMonitoring, "data")
		if !regexp.MustCompile(`(?m)^\s*(module|submodule)\s+` + regexp.QuoteMeta(m.Name) + `\s*\{`).MatchString(text) {
			t.Errorf("get-schema %s returned something else: %.200s", m.Name, text)
		}
	}
	reply, raw := c.rpc(`<get-schema xmlns="` + nsNetconfMonitoring + `"><identifier>ietf-alarms</identifier><version>1999-01-01</version></get-schema>`)
	mustRPCError(t, reply, raw, "invalid-value", "")
	reply, raw = c.rpc(`<get-schema xmlns="` + nsNetconfMonitoring + `"><identifier>ietf-alarms</identifier><format>yin</format></get-schema>`)
	mustRPCError(t, reply, raw, "invalid-value", "")
}

// TestNetconfEmbeddedModulesMatchProvenance ties the three descriptions of
// the schema together: the module table, the embedded files and
// SOURCES.tsv. Each file's digest is recomputed, and its module and
// revision statements must agree with its name.
func TestNetconfEmbeddedModulesMatchProvenance(t *testing.T) {
	recorded := map[string]string{}
	data, err := os.ReadFile("netconf_yang/SOURCES.tsv")
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			t.Fatalf("SOURCES.tsv row %q", line)
		}
		recorded[f[0]] = f[1]
	}
	entries, err := netconfYangFS.ReadDir("netconf_yang")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{}
	for _, e := range entries {
		files[e.Name()] = true
		b, _ := netconfYangFS.ReadFile("netconf_yang/" + e.Name())
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); recorded[e.Name()] != got {
			t.Errorf("%s: sha256 %s, SOURCES.tsv records %q", e.Name(), got, recorded[e.Name()])
		}
		name, rev, _ := strings.Cut(strings.TrimSuffix(e.Name(), ".yang"), "@")
		text := string(b)
		if !regexp.MustCompile(`(?m)^\s*module\s+` + regexp.QuoteMeta(name) + `\s*\{`).MatchString(text) {
			t.Errorf("%s does not declare module %s", e.Name(), name)
		}
		if m := regexp.MustCompile(`(?m)^\s*revision\s+"?(\d{4}-\d{2}-\d{2})"?`).FindStringSubmatch(text); m == nil || m[1] != rev {
			t.Errorf("%s: newest revision statement %v, file name says %s", e.Name(), m, rev)
		}
	}
	for _, m := range netconfModules {
		f := m.Name + "@" + m.Revision + ".yang"
		if !files[f] {
			t.Errorf("module %s is in the library but %s is not embedded", m.Name, f)
		}
		delete(files, f)
	}
	for f := range files {
		t.Errorf("%s is embedded but no library module names it", f)
	}
	for f := range recorded {
		if _, err := netconfYangFS.ReadFile("netconf_yang/" + f); err != nil {
			t.Errorf("SOURCES.tsv lists %s, which is not embedded", f)
		}
	}
}

func TestNetconfReplayBufferAgesOut(t *testing.T) {
	l := &netconfEventLog{created: time.Now(), alarms: map[int]*netconfAlarm{}, subs: map[*netconfSubscription]struct{}{}}
	base := time.Now()
	for i := 0; i < netconfReplayCapacity+10; i++ {
		l.mu.Lock()
		l.appendLocked(netconfEvent{at: base.Add(time.Duration(i) * time.Second), kind: netconfEventSessionStart, sessionID: uint32(i + 1)})
		l.mu.Unlock()
	}
	if got := l.replayFloor(); !got.Equal(base.Add(9 * time.Second)) {
		t.Fatalf("replay floor %v, want the newest aged record at +9s", got.Sub(base))
	}
	replayed := l.subscribe(&netconfSubscription{}, base)
	if len(replayed) != netconfReplayCapacity || replayed[0].sessionID != 11 || replayed[len(replayed)-1].sessionID != netconfReplayCapacity+10 {
		t.Fatalf("replay returned %d records from %d to %d", len(replayed), replayed[0].sessionID, replayed[len(replayed)-1].sessionID)
	}
}

func TestInterfaceStateObserverSeesEveryEventAndSurvivesPanics(t *testing.T) {
	dev := newTestGnmiDevice(t, 2)
	st := dev.metricsCycler.ifCounters.Load().State()
	var seen []int
	removePanicky := st.AddObserver(func(StateChange) { panic("observer bug") })
	remove := st.AddObserver(func(e StateChange) { seen = append(seen, e.IfIndex) })
	setLink(t, dev, 1, OperUp)
	setLink(t, dev, 1, OperDown)
	setAdmin(t, dev, 2, AdminDown)
	if len(seen) < 3 {
		t.Fatalf("observer after a panicking one saw %v", seen)
	}
	remove()
	removePanicky()
	remove() // removing twice is harmless
	n := len(seen)
	setLink(t, dev, 1, OperUp)
	if len(seen) != n {
		t.Fatal("a removed observer still runs")
	}
}
