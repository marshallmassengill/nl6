/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// netconfDefaultPort is the IANA port for NETCONF over TLS (RFC 7589 §6).
const netconfDefaultPort = 6513

// Client authentication modes reported by GET /api/v1/netconf/status.
const (
	netconfClientAuthVerified = "verified"
	netconfClientAuthAny      = "any-certificate"
)

// NetconfSubsystemConfig is the simulator-wide NETCONF configuration. The
// subsystem is OFF unless Enabled: unlike gNMI it is new, and turning it on
// by default would add a listener to every device of every existing fleet.
type NetconfSubsystemConfig struct {
	Enabled bool
	Port    int
	// CertPEM and KeyPEM are the server identity, both or neither. Neither
	// means the simulator's shared self-signed certificate, which is
	// regenerated at every start, so a collector pinning it by CA or
	// fingerprint has to re-pin after a restart; supplying a certificate
	// is how to avoid that.
	CertPEM, KeyPEM []byte
	// ClientCAPEM verifies client certificates. RFC 7589 is mutual TLS, so
	// a client certificate is ALWAYS required; without a CA any
	// certificate is accepted, which status reports as any-certificate.
	ClientCAPEM []byte
	// CallHome is the RFC 8071 Call Home client every device dials, as
	// host or host:port (port 4335 when omitted); empty means no device
	// calls home. The TLS identity and client verification are the ones
	// above: after the TCP connection the device is still the TLS server.
	CallHome string
	// CallHomeSubscriptions are the configured subscriptions (RFC 8639
	// §2.5) delivered over each Call Home session, in the syntax of
	// parseNetconfConfiguredSubscriptions. They need CallHome.
	CallHomeSubscriptions string
}

// netconfSubsystem is the manager's NETCONF state: configuration fixed at
// start plus counters that survive device churn.
type netconfSubsystem struct {
	active     atomic.Bool
	port       int
	tlsConfig  *tls.Config
	clientAuth string
	certSHA256 string
	certPrint  string // SHA256:<base64>
	callHome   string // host:port, empty when off
	configured []netconfConfiguredSubscription

	nextSessionID      atomic.Uint32
	nextSubscriptionID atomic.Uint32

	sessionsActive            atomic.Int64
	sessionsTotal             atomic.Uint64
	sessionsRefused           atomic.Uint64
	tlsHandshakeFailures      atomic.Uint64
	listenerAcceptFailures    atomic.Uint64
	helloFailures             atomic.Uint64
	rpcs                      atomic.Uint64
	rpcErrors                 atomic.Uint64
	subscriptionsActive       atomic.Int64
	pushUpdates               atomic.Uint64
	pushChangeUpdates         atomic.Uint64
	eventNotifications        atomic.Uint64
	streamRecordsDropped      atomic.Uint64
	notificationWriteFailures atomic.Uint64

	callHomeDials         atomic.Uint64
	callHomeDialFailures  atomic.Uint64
	callHomeSessionsTotal atomic.Uint64
	callHomeConnected     atomic.Int64

	firstHandshakeErr sync.Once
	firstHelloErr     sync.Once
	firstCallHomeErr  sync.Once
}

// NetconfStatus is the body of GET /api/v1/netconf/status.
type NetconfStatus struct {
	SubsystemActive bool   `json:"subsystem_active"`
	Port            int    `json:"port,omitempty"`
	ClientAuth      string `json:"client_auth,omitempty"`
	// ServerCertSHA256 is the leaf certificate's fingerprint in the colon
	// hex form OpenSSL prints, for a collector that pins by fingerprint.
	ServerCertSHA256 string `json:"server_cert_sha256,omitempty"`
	// ServerCertFingerprint is the same digest as SHA256:<base64>, without
	// padding: the form OpenSSH prints and OpenNMS's Call Home listener
	// logs and matches in allowedFingerprints.
	ServerCertFingerprint  string `json:"server_cert_fingerprint,omitempty"`
	Listeners              int    `json:"listeners"`
	SessionsActive         int64  `json:"sessions_active"`
	SessionsTotal          uint64 `json:"sessions_total"`
	SessionsRefused        uint64 `json:"sessions_refused"`
	TLSHandshakeFailures   uint64 `json:"tls_handshake_failures"`
	ListenerAcceptFailures uint64 `json:"listener_accept_failures"`
	HelloFailures          uint64 `json:"hello_failures"`
	RPCs                   uint64 `json:"rpcs"`
	RPCErrors              uint64 `json:"rpc_errors"`
	SubscriptionsActive    int64  `json:"subscriptions_active"`
	PushUpdates            uint64 `json:"push_updates"`
	PushChangeUpdates      uint64 `json:"push_change_updates"`
	// EventNotifications counts NETCONF-stream notifications sent:
	// alarm-notification, netconf-session-start and netconf-session-end.
	EventNotifications        uint64 `json:"event_notifications"`
	StreamRecordsDropped      uint64 `json:"stream_records_dropped"`
	NotificationWriteFailures uint64 `json:"notification_write_failures"`
	// CallHome is the Call Home client devices dial; the counters below
	// it are present only when it is set.
	CallHome                string   `json:"callhome,omitempty"`
	ConfiguredSubscriptions []string `json:"configured_subscriptions,omitempty"`
	CallHomeConnected       *int64   `json:"callhome_connected,omitempty"`
	CallHomeDials           *uint64  `json:"callhome_dials,omitempty"`
	CallHomeDialFailures    *uint64  `json:"callhome_dial_failures,omitempty"`
	CallHomeSessionsTotal   *uint64  `json:"callhome_sessions_total,omitempty"`
}

// StartNetconfSubsystem validates cfg and records it. With Enabled false it
// does nothing, and no device listens.
func (sm *SimulatorManager) StartNetconfSubsystem(cfg NetconfSubsystemConfig) error {
	if !cfg.Enabled {
		return nil
	}
	nc := &sm.netconf
	if nc.active.Load() {
		return fmt.Errorf("netconf: subsystem already started")
	}
	port := cfg.Port
	if port == 0 {
		port = netconfDefaultPort
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("netconf: invalid port %d (must be 1..65535)", port)
	}
	var cert tls.Certificate
	switch {
	case len(cfg.CertPEM) > 0 && len(cfg.KeyPEM) > 0:
		c, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
		if err != nil {
			return fmt.Errorf("netconf: server certificate: %v", err)
		}
		cert = c
	case len(cfg.CertPEM) > 0 || len(cfg.KeyPEM) > 0:
		return fmt.Errorf("netconf: -netconf-tls-cert and -netconf-tls-key go together")
	case sm.sharedTLSCert != nil:
		cert = *sm.sharedTLSCert
	default:
		return fmt.Errorf("netconf: no server certificate (the shared certificate was not generated and none was given)")
	}
	tc := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	nc.clientAuth = netconfClientAuthAny
	if len(cfg.ClientCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.ClientCAPEM) {
			return fmt.Errorf("netconf: client CA bundle holds no PEM certificate")
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
		nc.clientAuth = netconfClientAuthVerified
	}
	if cfg.CallHome == "" && cfg.CallHomeSubscriptions != "" {
		return fmt.Errorf("netconf: -netconf-callhome-subscriptions needs -netconf-callhome: configured subscriptions are delivered over Call Home")
	}
	if cfg.CallHome != "" {
		ch, err := netconfCallHomeAddress(cfg.CallHome)
		if err != nil {
			return err
		}
		subs, err := parseNetconfConfiguredSubscriptions(cfg.CallHomeSubscriptions)
		if err != nil {
			return err
		}
		nc.callHome, nc.configured = ch, subs
	}
	nc.tlsConfig = tc
	nc.port = port
	if len(cert.Certificate) > 0 {
		sum := sha256.Sum256(cert.Certificate[0])
		hexes := make([]string, len(sum))
		for i, b := range sum {
			hexes[i] = fmt.Sprintf("%02X", b)
		}
		nc.certSHA256 = strings.Join(hexes, ":")
		nc.certPrint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	}
	nc.active.Store(true)
	if nc.clientAuth == netconfClientAuthAny {
		log.Printf("NETCONF subsystem enabled on port %d (TLS, RFC 7589); client certificates are REQUIRED but NOT verified "+
			"(set -netconf-tls-client-ca to verify them). Server certificate SHA-256 %s", port, nc.certSHA256)
	} else {
		log.Printf("NETCONF subsystem enabled on port %d (TLS, RFC 7589); client certificates verified against "+
			"-netconf-tls-client-ca. Server certificate SHA-256 %s", port, nc.certSHA256)
	}
	if nc.callHome != "" {
		log.Printf("NETCONF Call Home over TLS (RFC 8071) to %s from every device, %d configured subscription(s)",
			nc.callHome, len(nc.configured))
	}
	return nil
}

// StopNetconfSubsystem stops every device's NETCONF server. Shutdown-only,
// like StopGnmiSubsystem: device attach reads the subsystem state without a
// lock that a runtime restart could take.
func (sm *SimulatorManager) StopNetconfSubsystem() {
	if !sm.netconf.active.Load() {
		return
	}
	sm.mu.RLock()
	devices := make([]*DeviceSimulator, 0, len(sm.devices))
	for _, d := range sm.devices {
		devices = append(devices, d)
	}
	sm.mu.RUnlock()
	for _, d := range devices {
		d.mu.Lock()
		d.stopNetconfServer()
		d.mu.Unlock()
	}
	sm.netconf.active.Store(false)
}

func (nc *netconfSubsystem) logFirstHandshakeError(d *DeviceSimulator, remote net.Addr, err error) {
	nc.firstHandshakeErr.Do(func() {
		log.Printf("netconf: TLS handshake from %v to device %s failed: %v (further failures are counted in "+
			"GET /api/v1/netconf/status tls_handshake_failures, not logged). A client must present a certificate (RFC 7589)",
			remote, d.IP, err)
	})
}

func (nc *netconfSubsystem) logFirstHelloError(d *DeviceSimulator, err error) {
	nc.firstHelloErr.Do(func() {
		log.Printf("netconf: hello exchange on device %s failed: %v (further failures are counted in hello_failures, not logged)",
			d.IP, err)
	})
}

// GetNetconfStatus snapshots the subsystem for the status endpoint.
func (sm *SimulatorManager) GetNetconfStatus() NetconfStatus {
	nc := &sm.netconf
	st := NetconfStatus{
		SubsystemActive:           nc.active.Load(),
		SessionsActive:            nc.sessionsActive.Load(),
		SessionsTotal:             nc.sessionsTotal.Load(),
		SessionsRefused:           nc.sessionsRefused.Load(),
		TLSHandshakeFailures:      nc.tlsHandshakeFailures.Load(),
		ListenerAcceptFailures:    nc.listenerAcceptFailures.Load(),
		HelloFailures:             nc.helloFailures.Load(),
		RPCs:                      nc.rpcs.Load(),
		RPCErrors:                 nc.rpcErrors.Load(),
		SubscriptionsActive:       nc.subscriptionsActive.Load(),
		PushUpdates:               nc.pushUpdates.Load(),
		PushChangeUpdates:         nc.pushChangeUpdates.Load(),
		EventNotifications:        nc.eventNotifications.Load(),
		StreamRecordsDropped:      nc.streamRecordsDropped.Load(),
		NotificationWriteFailures: nc.notificationWriteFailures.Load(),
	}
	if !st.SubsystemActive {
		return st
	}
	st.Port = nc.port
	st.ClientAuth = nc.clientAuth
	st.ServerCertSHA256 = nc.certSHA256
	st.ServerCertFingerprint = nc.certPrint
	if nc.callHome != "" {
		st.CallHome = nc.callHome
		for _, c := range nc.configured {
			st.ConfiguredSubscriptions = append(st.ConfiguredSubscriptions, c.String())
		}
		connected, dials, failures, total := nc.callHomeConnected.Load(), nc.callHomeDials.Load(),
			nc.callHomeDialFailures.Load(), nc.callHomeSessionsTotal.Load()
		st.CallHomeConnected, st.CallHomeDials, st.CallHomeDialFailures, st.CallHomeSessionsTotal = &connected, &dials, &failures, &total
	}
	sm.mu.RLock()
	for _, d := range sm.devices {
		d.mu.RLock()
		if d.netconfServer != nil {
			st.Listeners++
		}
		d.mu.RUnlock()
	}
	sm.mu.RUnlock()
	return st
}

// netconfStatusHandler serves GET /api/v1/netconf/status.
func netconfStatusHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(manager.GetNetconfStatus())
}
