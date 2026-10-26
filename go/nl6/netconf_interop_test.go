/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNetconfInterop is the external check. The in-package tests can only
// show that nl6 agrees with itself; this one hands nl6's output to libyang
// and libnetconf2, which know the YANG and the protocol independently:
//
//   - yanglint builds its schema from the YANG library nl6 SERVES (-Y), so
//     a wrong revision, a missing import or an unadvertised feature fails
//     here, and validates every shipped profile's operational and running
//     datastores under exactly that schema;
//   - yanglint validates live rpc-replies and the push-update,
//     push-change-update and subscription-terminated notifications, with
//     their NETCONF envelopes;
//   - netopeer2-cli runs a whole RFC 7589 session against the real
//     listener with mutual TLS: get-data, then an on-change establish-push
//     that must deliver the link flap the test causes.
//
// Run through `make test-interop-netconf`. yanglint searches nl6's own
// embedded modules (netconf_yang/) and nothing else, so it checks exactly
// what get-schema serves; netopeer2-cli gets no search path and has to fetch
// what it lacks (ietf-alarms, nl6-alarm-types, the RFC 6241 ietf-netconf)
// through get-schema.
func TestNetconfInterop(t *testing.T) {
	if os.Getenv("NL6_NETCONF_INTEROP") != "1" {
		t.Skip("set NL6_NETCONF_INTEROP=1 (make test-interop-netconf) to run against libyang and netopeer2-cli")
	}
	image := os.Getenv("NL6_NETCONF_IMAGE")
	if image == "" {
		image = "ghcr.io/notconf/notconf:debug"
	}
	yangDir, err := filepath.Abs("netconf_yang")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	docker := func(t *testing.T, network string, stdin string, args ...string) (string, error) {
		t.Helper()
		full := append([]string{"run", "--rm", "-i", "--network", network, "-v", work + ":/w", "-v", yangDir + ":/x:ro"}, args...)
		cmd := exec.Command("docker", full...)
		cmd.Stdin = strings.NewReader(stdin)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}

	var lib bytes.Buffer
	writeNetconfNodes(&lib, []*ncNode{netconfYangLibrary(), netconfModulesState()}, "")
	write("library.xml", lib.String())

	// Every check runs in one container, so the cost is one start.
	var script strings.Builder
	script.WriteString("set -e\nY='yanglint -D -Y /w/library.xml -p /x'\n")
	check := func(desc, args string) {
		fmt.Fprintf(&script, "echo %q; $Y %s\n", desc, args)
	}

	t.Run("collect shipped datastores", func(t *testing.T) {
		sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
		for _, profile := range shippedProfileNames(t) {
			srv := shippedNetconfServer(t, sm, profile)
			slug := strings.TrimSuffix(filepath.Base(profile), ".json")
			for _, ds := range []netconfDatastoreName{netconfOperational, netconfRunning} {
				var b bytes.Buffer
				writeNetconfNodes(&b, srv.datastore(ds, time.Now()), "")
				if b.Len() == 0 {
					continue
				}
				name := fmt.Sprintf("%s-%s.xml", ds, slug)
				write(name, b.String())
				// -e: validate against the modules whose data is present.
				// Without it, CESNET's `notifications` module (RFC 5277 in
				// YANG) demands its internal top-level container, whose
				// eventTime is mandatory, from every datastore; no server
				// holds that. Presence of what nl6 must serve is asserted by
				// TestNetconfOperationalServesEveryStateTree instead.
				if ds == netconfOperational {
					check(name, "-e -t data /w/"+name)
				} else {
					check(name, "-e -t config /w/"+name)
				}
			}
		}
	})

	pki := newTestPKI(t, "interop")
	serverCert, serverKey, _ := pki.issuePEM(t, "nl6-device", x509.ExtKeyUsageServerAuth)
	clientCert, clientKey, client := pki.issuePEM(t, "collector", x509.ExtKeyUsageClientAuth)
	write("ca.pem", string(pki.caPEM))
	write("client.pem", string(clientCert))
	write("client.key", string(clientKey))
	mgr, dev, addr := startTestNetconfWith(t, 3, NetconfSubsystemConfig{CertPEM: serverCert, KeyPEM: serverKey, ClientCAPEM: pki.caPEM},
		func(d *DeviceSimulator) { d.resources.oidIndex.Store(".1.3.6.1.2.1.2.2.1.2.1", "Gi0/1") })
	setLink(t, dev, 1, OperUp)

	t.Run("collect live replies and notifications", func(t *testing.T) {
		c := mustDialTestNetconf(t, addr, &client)
		n := 0
		replyCheck := func(op string) {
			reply, raw := c.rpc(op)
			mustNoRPCError(t, reply, raw)
			n++
			write(fmt.Sprintf("rpc-%d.xml", n), fmt.Sprintf(`<rpc xmlns="%s" message-id="%d">%s</rpc>`, nsNetconfBase, c.msgID, op))
			write(fmt.Sprintf("reply-%d.xml", n), raw)
			check(fmt.Sprintf("reply-%d.xml", n), fmt.Sprintf("-t nc-reply -R /w/rpc-%d.xml /w/reply-%d.xml", n, n))
		}
		notifCheck := func(raw string) {
			n++
			write(fmt.Sprintf("notif-%d.xml", n), raw)
			check(fmt.Sprintf("notif-%d.xml", n), fmt.Sprintf("-t nc-notif /w/notif-%d.xml", n))
		}
		replyCheck(`<get-data xmlns="` + nsNetconfNMDA + `" xmlns:ds="` + nsDatastores + `"><datastore>ds:operational</datastore></get-data>`)
		replyCheck(`<get-data xmlns="` + nsNetconfNMDA + `" xmlns:ds="` + nsDatastores + `"><datastore>ds:operational</datastore><config-filter>false</config-filter></get-data>`)
		replyCheck(`<get/>`)
		replyCheck(`<get-config><source><running/></source></get-config>`)
		stop := time.Now().Add(1500 * time.Millisecond).UTC().Format(time.RFC3339Nano)
		replyCheck(strings.Replace(fmt.Sprintf(establishOnChange, "", ""), "<yp:on-change>", "<stop-time>"+stop+"</stop-time><yp:on-change>", 1))
		_, raw := c.next(5 * time.Second) // sync push-update
		notifCheck(raw)
		setLink(t, dev, 1, OperDown)
		_, raw = c.next(5 * time.Second) // push-change-update
		if !strings.Contains(raw, "push-change-update") {
			t.Fatalf("expected push-change-update: %s", raw)
		}
		notifCheck(raw)
		_, raw = c.next(5 * time.Second) // subscription-terminated at stop-time
		notifCheck(raw)
		replyCheck(fmt.Sprintf(establishPeriodic, "", 100))
		_, raw = c.next(5 * time.Second)
		notifCheck(raw)

		// The event stream: alarms, session events, replay, termination.
		swap := c
		c = mustDialTestNetconf(t, addr, &client)
		replyCheck(`<get><filter type="subtree"><alarms xmlns="` + nsAlarms + `"/><streams xmlns="` + nsSubscribedNotif + `"/></filter></get>`)
		replyCheck(`<get-schema xmlns="` + nsNetconfMonitoring + `"><identifier>nl6-alarm-types</identifier></get-schema>`)
		stop = time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339Nano)
		replyCheck(fmt.Sprintf(establishStream, "", "<replay-start-time>2001-01-01T00:00:00Z</replay-start-time><stop-time>"+stop+"</stop-time>"))
		// The replay holds the alarm raised above and the session-starts;
		// read up to replay-completed.
		for {
			el, raw := c.next(5 * time.Second)
			notifCheck(raw)
			if el.Child(nsSubscribedNotif, "replay-completed") != nil {
				break
			}
		}
		setLink(t, dev, 1, OperUp) // the alarm clears, live
		_, raw = c.next(5 * time.Second)
		if !strings.Contains(raw, ">cleared</perceived-severity>") {
			t.Fatalf("expected the clear: %s", raw)
		}
		notifCheck(raw)
		swap.sendRaw(`<rpc xmlns="` + nsNetconfBase + `" message-id="99"><close-session/></rpc>`)
		_, raw = c.next(5 * time.Second) // netconf-session-end of the first client
		if !strings.Contains(raw, "netconf-session-end") {
			t.Fatalf("expected netconf-session-end: %s", raw)
		}
		notifCheck(raw)
		_, raw = c.next(5 * time.Second) // subscription-terminated at stop-time
		notifCheck(raw)

		// RFC 5277: create-subscription with replay up to a stopTime.
		c = mustDialTestNetconf(t, addr, &client)
		replyCheck(`<create-subscription xmlns="` + nsNetconfNotif + `"><startTime>2001-01-01T00:00:00Z</startTime><stopTime>` +
			time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano) + `</stopTime></create-subscription>`)
		for {
			el, raw := c.next(5 * time.Second)
			notifCheck(raw)
			if el.Child(nsNetmodNotification, "notificationComplete") != nil {
				break
			}
		}
	})

	t.Run("yanglint", func(t *testing.T) {
		// Zero documents passes yanglint trivially, which is what running
		// this subtest alone (-run .../yanglint) used to do.
		if docs := strings.Count(script.String(), "\necho "); docs < 60 {
			t.Fatalf("only %d documents collected; run the whole TestNetconfInterop", docs)
		}
		out, err := docker(t, "none", script.String(), "--entrypoint", "sh", image, "-s")
		if err != nil {
			t.Fatalf("yanglint rejected nl6 output: %v\n%s", err, tail(out, 60))
		}
		t.Logf("yanglint accepted %d documents", strings.Count(script.String(), "\necho "))
	})

	t.Run("netopeer2-cli", func(t *testing.T) {
		setLink(t, dev, 1, OperUp)
		// A subtree filter: get-data's xpath-filter is `if-feature
		// ietf-netconf:xpath`, which nl6 does not claim (it serves an XPath
		// subset), so libnetconf2 rightly refuses to build that RPC.
		write("filter.xml", `<interfaces xmlns="`+nsIETFInterfaces+`"><interface><name>Gi0/1</name><oper-status/></interface></interfaces>`)
		host, port, _ := net.SplitHostPort(addr)
		before := mgr.netconf.pushChangeUpdates.Load()
		// libnetconf2 reads the schema with requests nl6's own client never
		// sends (get-data with config-filter was the first); any it refuses
		// shows up here even when the CLI recovers by falling back.
		errorsBefore := mgr.netconf.rpcErrors.Load()
		alarmsBefore := mgr.netconf.eventNotifications.Load()
		cmds := fmt.Sprintf("connect --tls --host %s --port %s --cert /w/client.pem --key /w/client.key --trusted /w/ca.pem\n"+
			"get-data --datastore operational --filter-subtree=/w/filter.xml\n"+
			"establish-sub --stream NETCONF --filter-xpath /ietf-alarms:alarm-notification\n"+
			"establish-push --datastore operational --on-change --no-sync-on-start\n", host, port)
		type result struct {
			out string
			err error
		}
		done := make(chan result, 1)
		go func() {
			// The sleep holds stdin open so the session lives while the
			// test flips the link.
			out, err := docker(t, "host", "", "--entrypoint", "sh", image, "-c",
				fmt.Sprintf("(printf '%%b' %q; sleep 6; printf 'disconnect\\nquit\\n') | netopeer2-cli", cmds))
			done <- result{out, err}
		}()
		deadline := time.Now().Add(20 * time.Second)
		for mgr.netconf.subscriptionsActive.Load() < 2 {
			if time.Now().After(deadline) {
				r := <-done
				t.Fatalf("netopeer2-cli never established a subscription: %v\n%s", r.err, tail(r.out, 60))
			}
			time.Sleep(50 * time.Millisecond)
		}
		setLink(t, dev, 1, OperDown)
		r := <-done
		if r.err != nil {
			t.Fatalf("netopeer2-cli: %v\n%s", r.err, tail(r.out, 60))
		}
		if n := mgr.netconf.rpcErrors.Load() - errorsBefore; n != 0 {
			t.Errorf("nl6 answered %d of netopeer2-cli's requests with rpc-error:\n%s", n, tail(r.out, 60))
		}
		if mgr.netconf.pushChangeUpdates.Load() == before {
			t.Fatalf("no push-change-update was sent to netopeer2-cli:\n%s", tail(r.out, 60))
		}
		if mgr.netconf.eventNotifications.Load() == alarmsBefore {
			t.Fatalf("no alarm-notification was sent to netopeer2-cli:\n%s", tail(r.out, 60))
		}
		for _, want := range []string{"<oper-status", ">up</oper-status>", "push-change-update", "interface=Gi0%2F1/oper-status",
			"<alarm-notification", "nl6-at:link-down", "<perceived-severity>major</perceived-severity>"} {
			if !strings.Contains(r.out, want) {
				t.Errorf("netopeer2-cli output lacks %q:\n%s", want, tail(r.out, 60))
			}
		}
		for _, bad := range []string{"ERROR", "nc_err", "libyang["} {
			if strings.Contains(r.out, bad) {
				t.Errorf("netopeer2-cli reported %q:\n%s", bad, tail(r.out, 60))
			}
		}
	})
}

func tail(s string, lines int) string {
	ls := strings.Split(s, "\n")
	if len(ls) > lines {
		ls = ls[len(ls)-lines:]
	}
	return strings.Join(ls, "\n")
}
