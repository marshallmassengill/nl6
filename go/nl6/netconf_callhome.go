/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// NETCONF Call Home over TLS (RFC 8071 §4.1). Each device dials the
// configured client from its own address and, once the TCP connection is
// up, is the TLS server and the NETCONF server on it: everything after the
// connect is the RFC 7589 path a listener-accepted connection takes. The
// connection is persistent: when it ends the device dials again, with
// capped, jittered backoff.
//
// Configured subscriptions (RFC 8639 §2.5) ride on the Call Home session.
// The Call Home client is their one receiver: each session opens with a
// subscription-started per configured subscription, and the receiver is
// back to connecting while no session is up. Records produced while it is
// disconnected are not replayed to it.

const (
	// netconfCallHomeDefaultPort is the IANA port for NETCONF Call Home
	// over TLS (RFC 8071 §6).
	netconfCallHomeDefaultPort = 4335

	netconfCallHomeInitialBackoff = time.Second
	netconfCallHomeMaxBackoff     = 30 * time.Second
	// netconfCallHomeResetDwell is how long a session must last before the
	// next dial starts again from the initial backoff. A client that
	// accepts and drops at once would otherwise be redialled every second
	// by every device.
	netconfCallHomeResetDwell = 30 * time.Second

	// netconfCallHomeMaxConcurrentDials bounds concurrent in-namespace
	// dials across the fleet. DialContextInNamespace pins an OS thread for
	// the connect, so this cap, not the device count, bounds pinned threads
	// while the client is unreachable; it is gNMI dial-out's constant.
	netconfCallHomeMaxConcurrentDials = 64
	netconfCallHomeDialTimeout        = 10 * time.Second

	// netconfMaxConfiguredSubscriptions bounds -netconf-callhome-subscriptions.
	// Configured subscriptions take ids 1 to this; dynamic ones start at
	// netconfFirstDynamicSubscriptionID, so the two never collide.
	netconfMaxConfiguredSubscriptions = 8
	netconfFirstDynamicSubscriptionID = 100

	// netconfCallHomeReceiver names the configured subscriptions' receiver
	// in /subscriptions.
	netconfCallHomeReceiver  = "call-home"
	netconfConfiguredPurpose = "configured by nl6 -netconf-callhome-subscriptions"
)

var netconfCallHomeDialSem = make(chan struct{}, netconfCallHomeMaxConcurrentDials)

// netconfCallHomeAddress canonicalises -netconf-callhome: host or host:port,
// with an IPv6 literal bracketed when it carries a port.
func netconfCallHomeAddress(v string) (string, error) {
	v = strings.TrimSpace(v)
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		host, port = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]"), strconv.Itoa(netconfCallHomeDefaultPort)
	}
	if host == "" || strings.ContainsAny(host, " /") {
		return "", fmt.Errorf("netconf: -netconf-callhome %q is not host or host:port", v)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("netconf: -netconf-callhome %q has an invalid port (must be 1..65535)", v)
	}
	return net.JoinHostPort(host, port), nil
}

type netconfConfiguredKind uint8

const (
	netconfConfiguredStream netconfConfiguredKind = iota + 1
	netconfConfiguredOnChange
	netconfConfiguredPeriodic
)

// netconfConfiguredSubscription is one entry of
// -netconf-callhome-subscriptions. The datastore kinds select
// /ietf-interfaces:interfaces of the operational datastore; the stream kind
// is the whole NETCONF stream.
type netconfConfiguredSubscription struct {
	ID     uint32
	Kind   netconfConfiguredKind
	Period time.Duration // periodic only
}

func (c netconfConfiguredSubscription) String() string {
	switch c.Kind {
	case netconfConfiguredStream:
		return "stream"
	case netconfConfiguredOnChange:
		return "on-change"
	default:
		return "periodic=" + c.Period.String()
	}
}

// parseNetconfConfiguredSubscriptions reads a comma-separated list of
// `stream`, `on-change` and `periodic=<duration>`. Ids are assigned in list
// order from 1, so a collector sees the same id for the same entry on
// every device and across restarts.
func parseNetconfConfiguredSubscriptions(v string) ([]netconfConfiguredSubscription, error) {
	var out []netconfConfiguredSubscription
	seen := map[string]bool{}
	for _, raw := range strings.Split(v, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		c := netconfConfiguredSubscription{ID: uint32(len(out) + 1)}
		switch {
		case item == "stream":
			c.Kind = netconfConfiguredStream
		case item == "on-change":
			c.Kind = netconfConfiguredOnChange
		case strings.HasPrefix(item, "periodic="):
			d, err := time.ParseDuration(strings.TrimPrefix(item, "periodic="))
			if err != nil {
				return nil, fmt.Errorf("netconf: -netconf-callhome-subscriptions %q: %v", item, err)
			}
			if d < netconfMinPeriod {
				return nil, fmt.Errorf("netconf: -netconf-callhome-subscriptions %q: period below the minimum of %s", item, netconfMinPeriod)
			}
			if d%(10*time.Millisecond) != 0 {
				return nil, fmt.Errorf("netconf: -netconf-callhome-subscriptions %q: a period is whole centiseconds (RFC 8641)", item)
			}
			c.Kind, c.Period = netconfConfiguredPeriodic, d
		default:
			return nil, fmt.Errorf("netconf: -netconf-callhome-subscriptions %q is not stream, on-change or periodic=<duration>", item)
		}
		if seen[c.String()] {
			return nil, fmt.Errorf("netconf: -netconf-callhome-subscriptions lists %q twice", c.String())
		}
		seen[c.String()] = true
		if len(out) == netconfMaxConfiguredSubscriptions {
			return nil, fmt.Errorf("netconf: -netconf-callhome-subscriptions lists more than %d subscriptions", netconfMaxConfiguredSubscriptions)
		}
		out = append(out, c)
	}
	return out, nil
}

// netconfConfiguredState is one configured subscription on one device. It
// outlives Call Home sessions: the receiver's counters and state are
// properties of the configuration, not of a connection.
type netconfConfiguredState struct {
	cfg    netconfConfiguredSubscription
	sent   atomic.Uint64
	active atomic.Bool // receiver state active; connecting otherwise
}

// policy is the subscription-policy content shared by subscription-started
// and the /subscriptions entry, so the two cannot describe the
// subscription differently.
func (c netconfConfiguredSubscription) policy() []*ncNode {
	sn := nsSubscribedNotif
	encoding := &ncNode{NS: sn, Name: "encoding", Value: "sn:encode-xml", Leaf: true, ValuePrefix: "sn", ValueNS: sn}
	purpose := ncLeaf(sn, "purpose", netconfConfiguredPurpose)
	if c.Kind == netconfConfiguredStream {
		return []*ncNode{ncLeaf(sn, "stream", netconfStreamName), encoding, purpose}
	}
	out := []*ncNode{
		{NS: nsYangPush, Name: "datastore", Value: "ds:operational", Leaf: true, ValuePrefix: "ds", ValueNS: nsDatastores},
		{NS: nsYangPush, Name: "datastore-xpath-filter", Value: "/if:interfaces", Leaf: true, ValuePrefix: "if", ValueNS: nsIETFInterfaces},
		encoding, purpose,
	}
	if c.Kind == netconfConfiguredPeriodic {
		cs := strconv.FormatInt(int64(c.Period/(10*time.Millisecond)), 10)
		return append(out, ncContainer(nsYangPush, "periodic", ncLeaf(nsYangPush, "period", cs)))
	}
	return append(out, ncContainer(nsYangPush, "on-change", ncLeaf(nsYangPush, "sync-on-start", "true")))
}

// netconfInterfacesFilter selects /ietf-interfaces:interfaces, the target
// of the configured datastore subscriptions.
var netconfInterfacesFilter = []*filterNode{{NS: nsIETFInterfaces, Name: "interfaces"}}

// subscription instantiates the configured subscription on a Call Home
// session.
func (st *netconfConfiguredState) subscription(s *netconfSession) *netconfSubscription {
	sub := &netconfSubscription{id: st.cfg.ID, sess: s, configured: st, syncOnStart: true, excluded: map[string]bool{}}
	switch st.cfg.Kind {
	case netconfConfiguredStream:
		sub.stream = true
	case netconfConfiguredOnChange:
		sub.datastore, sub.filter, sub.filtered = netconfOperational, netconfInterfacesFilter, true
	case netconfConfiguredPeriodic:
		sub.datastore, sub.filter, sub.filtered = netconfOperational, netconfInterfacesFilter, true
		sub.periodic, sub.period = true, st.cfg.Period
	}
	return sub
}

// startConfigured opens a Call Home session's configured subscriptions,
// each announced by subscription-started before its first record (RFC 8639
// §2.5.1). It reports false when the session ended under it.
func (s *netconfSession) startConfigured() bool {
	nc := &s.srv.mgr.netconf
	for _, st := range s.srv.configured {
		sub := st.subscription(s)
		sub.quit = make(chan struct{})
		s.subsMu.Lock()
		if s.subs == nil {
			s.subsMu.Unlock()
			return false
		}
		s.subs[sub.id] = sub
		s.subsMu.Unlock()
		nc.subscriptionsActive.Add(1)
		started := ncContainer(nsSubscribedNotif, "subscription-started",
			append([]*ncNode{ncLeaf(nsSubscribedNotif, "id", strconv.FormatUint(uint64(st.cfg.ID), 10))}, st.cfg.policy()...)...)
		var b bytes.Buffer
		writeNetconfNode(&b, started, "")
		st.sent.Store(0) // RFC 8639: counted from the receiver's start
		if s.sendNotification(time.Now(), b.String()) != nil {
			return false
		}
		st.active.Store(true)
		sub.start()
	}
	return true
}

// subscriptionsNode is /subscriptions: the configured subscriptions, with
// their receiver's state in the operational datastore. nil when there are
// none. Dynamic subscriptions are not listed.
func (srv *netconfServer) subscriptionsNode(config bool) *ncNode {
	if len(srv.configured) == 0 {
		return nil
	}
	sn := nsSubscribedNotif
	subs := ncContainer(sn, "subscriptions")
	for _, st := range srv.configured {
		e := ncContainer(sn, "subscription", ncLeaf(sn, "id", strconv.FormatUint(uint64(st.cfg.ID), 10)))
		e.Children = append(e.Children, st.cfg.policy()...)
		recv := ncContainer(sn, "receiver", ncLeaf(sn, "name", netconfCallHomeReceiver))
		if !config {
			e.Children = append(e.Children, ncLeaf(sn, "configured-subscription-state", "valid"))
			state := "connecting"
			if st.active.Load() {
				state = "active"
			}
			recv.Children = append(recv.Children,
				ncLeaf(sn, "sent-event-records", strconv.FormatUint(st.sent.Load(), 10)),
				ncLeaf(sn, "excluded-event-records", "0"),
				ncLeaf(sn, "state", state))
		}
		e.Children = append(e.Children, ncContainer(sn, "receivers", recv))
		subs.Children = append(subs.Children, e)
	}
	return subs
}

// netconfCallHome is one device's persistent Call Home connection.
type netconfCallHome struct {
	srv    *netconfServer
	addr   string
	ctx    context.Context
	cancel context.CancelFunc
	dial   func(ctx context.Context) (net.Conn, error)
}

// startCallHome starts the dial loop; stopNetconfServer cancels it and
// waits for it through srv.wg. Caller holds d.mu.
func (srv *netconfServer) startCallHome(addr string) {
	for _, c := range srv.mgr.netconf.configured {
		srv.configured = append(srv.configured, &netconfConfiguredState{cfg: c})
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch := &netconfCallHome{srv: srv, addr: addr, ctx: ctx, cancel: cancel, dial: netconfCallHomeDialer(srv.dev, addr)}
	srv.callHome = ch
	srv.wg.Add(1)
	go ch.run()
}

// netconfCallHomeDialer dials from inside the device's netns with source IP
// = device IP, which is how a collector resolves the device by address
// (OpenNMS's Call Home listener matches the source to a node). Without a
// namespace (tests, -no-namespace) it dials from the host.
func netconfCallHomeDialer(d *DeviceSimulator, addr string) func(ctx context.Context) (net.Conn, error) {
	if d == nil || d.netNamespace == nil {
		return func(ctx context.Context) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "tcp", addr)
		}
	}
	ns, localIP := d.netNamespace, append(net.IP(nil), d.IP...)
	return func(ctx context.Context) (net.Conn, error) {
		return ns.DialContextInNamespace(ctx, "tcp", addr, &net.TCPAddr{IP: localIP})
	}
}

func (ch *netconfCallHome) run() {
	defer ch.srv.wg.Done()
	nc := &ch.srv.mgr.netconf
	backoff := netconfCallHomeInitialBackoff
	for ch.ctx.Err() == nil {
		nc.callHomeDials.Add(1)
		conn, err := ch.dialOnce()
		if err != nil {
			if ch.ctx.Err() != nil {
				return
			}
			nc.callHomeDialFailures.Add(1)
			nc.firstCallHomeErr.Do(func() {
				log.Printf("netconf: Call Home from device %s to %s failed: %v (devices keep redialling with backoff up to %s; "+
					"further failures are counted in callhome_dial_failures, not logged)", ch.srv.dev.IP, ch.addr, err, netconfCallHomeMaxBackoff)
			})
		} else {
			opened := time.Now()
			// Closing the connection on cancel ends a handshake or session in
			// progress, so stopping the device does not wait for a timeout.
			stop := context.AfterFunc(ch.ctx, func() { _ = conn.Close() })
			nc.callHomeConnected.Add(1)
			if ch.srv.serveTLS(conn, true) {
				nc.callHomeSessionsTotal.Add(1)
			}
			nc.callHomeConnected.Add(-1)
			stop()
			_ = conn.Close()
			if time.Since(opened) >= netconfCallHomeResetDwell {
				backoff = netconfCallHomeInitialBackoff
			}
		}
		if !ch.sleep(&backoff) {
			return
		}
	}
}

// dialOnce performs one bounded, throttled dial.
func (ch *netconfCallHome) dialOnce() (net.Conn, error) {
	select {
	case netconfCallHomeDialSem <- struct{}{}:
		defer func() { <-netconfCallHomeDialSem }()
	case <-ch.ctx.Done():
		return nil, ch.ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ch.ctx, netconfCallHomeDialTimeout)
	defer cancel()
	conn, err := ch.dial(ctx)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		// The listener path caps its buffers the same way; at fleet scale
		// the kernel's auto-tuned default is the difference that matters.
		_ = tc.SetWriteBuffer(tcpListenSocketBufSize)
		_ = tc.SetReadBuffer(tcpListenSocketBufSize)
		_ = tc.SetKeepAlive(true)
	}
	return conn, nil
}

// sleep waits a jittered backoff, between half and all of it, then doubles
// it up to the cap. The jitter matters when a client restarts: every device
// lost its session at the same instant and would otherwise redial in
// lockstep. Reports false when the device is stopping.
func (ch *netconfCallHome) sleep(backoff *time.Duration) bool {
	d := *backoff/2 + rand.N(*backoff/2+1) //nolint:gosec // jitter, not security
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch.ctx.Done():
		return false
	case <-t.C:
	}
	*backoff = min(*backoff*2, netconfCallHomeMaxBackoff)
	return true
}
