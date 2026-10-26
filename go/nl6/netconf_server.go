/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// netconfMaxSessionsPerDevice caps concurrent connections on one device. A
// collector such as OpenNMS opens one session per subscription, so a few
// are normal; the cap bounds a runaway client. A connection over the cap is
// closed before the TLS handshake and counted in sessions_refused.
const netconfMaxSessionsPerDevice = 16

// netconfStopTimeout bounds how long stopping a device waits for its
// session goroutines to return after their connections are closed.
const netconfStopTimeout = 2 * time.Second

// netconfServer is one device's NETCONF-over-TLS listener (RFC 7589).
type netconfServer struct {
	dev *DeviceSimulator
	mgr *SimulatorManager
	ln  net.Listener
	wg  sync.WaitGroup

	mu        sync.Mutex
	sessions  map[uint32]*netconfSession
	lockOwner uint32 // session holding the running datastore lock, 0 for none
	closed    bool

	conns atomic.Int32 // accepted connections not yet finished

	// events is the device's NETCONF stream and alarm list, live from
	// startNetconfServer to stopNetconfServer.
	events *netconfEventLog

	view atomic.Pointer[netconfIfaces]
}

// startNetconfServer binds the device's listener, inside its netns when it
// has one. Caller holds d.mu, as for startGnmiServer.
func (d *DeviceSimulator) startNetconfServer(port int) error {
	mgr := manager
	if mgr == nil {
		return fmt.Errorf("simulator manager not initialised")
	}
	addr := net.JoinHostPort(d.IP.String(), fmt.Sprint(port))
	var ln net.Listener
	var err error
	if d.netNamespace != nil {
		ln, err = d.netNamespace.ListenTCPInNamespace("tcp", addr)
	} else {
		lc := net.ListenConfig{Control: setSocketBufferSize}
		ln, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to start NETCONF server on %s: %v", addr, err)
	}
	srv := &netconfServer{dev: d, mgr: mgr, ln: ln, sessions: map[uint32]*netconfSession{}}
	srv.events = newNetconfEventLog(srv)
	d.netconfServer = srv
	srv.wg.Add(1)
	go srv.acceptLoop()
	return nil
}

// stopNetconfServer closes the listener and every session. Idempotent;
// caller holds d.mu. Session goroutines take no device lock, so waiting for
// them here cannot deadlock.
func (d *DeviceSimulator) stopNetconfServer() {
	srv := d.netconfServer
	if srv == nil {
		return
	}
	d.netconfServer = nil
	srv.mu.Lock()
	srv.closed = true
	sessions := make([]*netconfSession, 0, len(srv.sessions))
	for _, s := range srv.sessions {
		sessions = append(sessions, s)
	}
	srv.mu.Unlock()
	_ = srv.ln.Close()
	for _, s := range sessions {
		s.closeWith("other", 0) // RFC 6470: the server ended it
	}
	done := make(chan struct{})
	go func() {
		srv.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(netconfStopTimeout):
	}
	srv.events.close()
}

func (srv *netconfServer) acceptLoop() {
	defer srv.wg.Done()
	nc := &srv.mgr.netconf
	for {
		conn, err := srv.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			nc.listenerAcceptFailures.Add(1)
			time.Sleep(50 * time.Millisecond) // fd exhaustion: do not spin
			continue
		}
		// Counted from Accept, not from session registration, so connections
		// still in their handshake hold a slot too.
		if srv.conns.Add(1) > netconfMaxSessionsPerDevice {
			srv.conns.Add(-1)
			nc.sessionsRefused.Add(1)
			_ = conn.Close()
			continue
		}
		srv.wg.Add(1)
		go srv.serveConn(conn)
	}
}

// serveConn runs the TLS handshake and then the session.
func (srv *netconfServer) serveConn(raw net.Conn) {
	defer srv.wg.Done()
	defer srv.conns.Add(-1)
	nc := &srv.mgr.netconf
	conn := tls.Server(raw, nc.tlsConfig)
	_ = conn.SetDeadline(time.Now().Add(netconfHelloTimeout))
	if err := conn.Handshake(); err != nil {
		nc.tlsHandshakeFailures.Add(1)
		nc.logFirstHandshakeError(srv.dev, raw.RemoteAddr(), err)
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	s := &netconfSession{
		id:   nc.nextSessionID.Add(1),
		srv:  srv,
		conn: conn,
		rd:   newNetconfReader(conn, netconfMaxMessageBytes),
		subs: map[uint32]*netconfSubscription{},
		done: make(chan struct{}),
	}
	if cs := conn.ConnectionState(); len(cs.PeerCertificates) > 0 {
		s.user = cs.PeerCertificates[0].Subject.CommonName
	}
	if s.user == "" {
		s.user = "unknown" // RFC 6470 username is mandatory
	}
	if host, _, err := net.SplitHostPort(raw.RemoteAddr().String()); err == nil {
		s.source = host
	}
	srv.mu.Lock()
	if srv.closed {
		srv.mu.Unlock()
		_ = conn.Close()
		return
	}
	srv.sessions[s.id] = s
	srv.mu.Unlock()
	nc.sessionsActive.Add(1)
	nc.sessionsTotal.Add(1)
	s.run()
}

func (srv *netconfServer) removeSession(s *netconfSession) {
	srv.mu.Lock()
	if srv.sessions[s.id] == s {
		delete(srv.sessions, s.id)
		srv.mgr.netconf.sessionsActive.Add(-1)
	}
	if srv.lockOwner == s.id {
		srv.lockOwner = 0
	}
	srv.mu.Unlock()
}

func (srv *netconfServer) session(id uint32) *netconfSession {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.sessions[id]
}

// lockRunning takes the running datastore lock for id. It returns 0 on
// success, else the holder; RFC 6241 §7.5 denies a lock already held, even
// by the requesting session.
func (srv *netconfServer) lockRunning(id uint32) uint32 {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.lockOwner != 0 {
		return srv.lockOwner
	}
	srv.lockOwner = id
	return 0
}

func (srv *netconfServer) unlockRunning(id uint32) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.lockOwner != id {
		return false
	}
	srv.lockOwner = 0
	return true
}

func (srv *netconfServer) ifCounters() *IfCounterCycler {
	if srv.dev == nil || srv.dev.metricsCycler == nil {
		return nil
	}
	return srv.dev.metricsCycler.ifCounters.Load()
}

// ifaces returns the device's interface list, built on first use and
// rebuilt only if the cycler is replaced.
func (srv *netconfServer) ifaces() *netconfIfaces {
	ic := srv.ifCounters()
	if ic == nil {
		return nil
	}
	if v := srv.view.Load(); v != nil && v.ic == ic {
		return v
	}
	v := buildNetconfIfaces(srv.dev, ic)
	srv.view.Store(v)
	return v
}

// datastore renders the top-level nodes of ds at now. The operational
// datastore is the one `get` answers from too: it already holds the config
// nodes in use.
func (srv *netconfServer) datastore(ds netconfDatastoreName, now time.Time) []*ncNode {
	var out []*ncNode
	if v := srv.ifaces(); v != nil && len(v.indices) > 0 {
		tSec := now.Sub(v.ic.startTime).Seconds()
		ifs := ncContainer(nsIETFInterfaces, "interfaces")
		for _, idx := range v.indices {
			ifs.Children = append(ifs.Children, v.entry(idx, ds == netconfRunning, tSec))
		}
		out = append(out, ifs)
	}
	if ds == netconfOperational {
		out = append(out, netconfYangLibrary(), netconfModulesState(), netconfMonitoringSchemas())
		if srv.events != nil {
			out = append(out, srv.events.alarmsNode(), srv.events.streamsNode(), srv.events.netconfStreamsNode())
		}
	}
	return out
}
