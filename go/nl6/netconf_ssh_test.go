/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	testSSHSignerOnce sync.Once
	testSSHSigner     ssh.Signer
)

// testNetconfSSHSigner is a host key for test managers, made once: an
// ed25519 key costs nothing, but one per test is noise.
func testNetconfSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	testSSHSignerOnce.Do(func() {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		testSSHSigner, err = ssh.NewSignerFromKey(key)
		if err != nil {
			panic(err)
		}
	})
	return testSSHSigner
}

// newTestSSHKey returns a client key and its authorized_keys line.
func newTestSSHKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	testSSHKeysMu.Lock()
	testSSHKeys[ssh.FingerprintSHA256(signer.PublicKey())] = key
	testSSHKeysMu.Unlock()
	return signer, ssh.MarshalAuthorizedKey(signer.PublicKey())
}

// testSSHKeys keeps newTestSSHKey's private keys, for a test that hands one
// to an external client.
var (
	testSSHKeysMu sync.Mutex
	testSSHKeys   = map[string]ed25519.PrivateKey{}
)

// sshTestConn is a client netconf channel as an ncTestConn. A deadline is
// set on the socket under it, which ends the whole SSH connection when it
// passes, as it ends a TLS connection.
type sshTestConn struct {
	raw    net.Conn
	client *ssh.Client
	sess   *ssh.Session
	in     io.WriteCloser
	out    io.Reader
}

func (c *sshTestConn) Read(p []byte) (int, error)    { return c.out.Read(p) }
func (c *sshTestConn) Write(p []byte) (int, error)   { return c.in.Write(p) }
func (c *sshTestConn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }
func (c *sshTestConn) Close() error                  { _ = c.sess.Close(); return c.client.Close() }

// openTestSSH runs the SSH client handshake on raw and opens the netconf
// subsystem. hostKey, when non-nil, receives the server's key.
func openTestSSH(raw net.Conn, user string, auth []ssh.AuthMethod, hostKey *ssh.PublicKey) (*sshTestConn, error) {
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if hostKey != nil {
				*hostKey = key
			}
			return nil
		},
	}
	cc, chans, reqs, err := ssh.NewClientConn(raw, raw.RemoteAddr().String(), cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	client := ssh.NewClient(cc, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.RequestSubsystem(netconfSSHSubsystem); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &sshTestConn{raw: raw, client: client, sess: sess, in: in, out: out}, nil
}

func dialTestNetconfSSH(t *testing.T, addr, user string, auth ...ssh.AuthMethod) (*ncTestClient, error) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := openTestSSH(raw, user, auth, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return helloTestNetconf(t, conn, true)
}

// startTestNetconfSSH runs a device with the SSH listener, returning its
// address.
func startTestNetconfSSH(t *testing.T, ifCount int, cfg NetconfSubsystemConfig) (*SimulatorManager, *DeviceSimulator, string) {
	t.Helper()
	cfg.SSHEnabled = true
	if cfg.SSHPort == 0 {
		cfg.SSHPort = freeTestPort(t)
	}
	mgr, dev, _ := startTestNetconf(t, ifCount, cfg)
	return mgr, dev, dev.netconfServer.sshLn.Addr().String()
}

func freeTestPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func keyboardInteractive(password string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = password
		}
		return answers, nil
	})
}

// TestNetconfSSHServesTheSameSession: over SSH the operations, the hello
// and the event stream are the TLS session's, and the RFC 6470 username is
// the SSH login.
func TestNetconfSSHServesTheSameSession(t *testing.T) {
	pki := newTestPKI(t, "collector")
	mgr, _, sshAddr := startTestNetconfSSH(t, 2, NetconfSubsystemConfig{SSHPassword: "secret"})
	tlsAddr := mgr.devices["test"].netconfServer.ln.Addr().String()

	watcher := mustDialTestNetconf(t, tlsAddr, &pki.client)
	reply, raw := watcher.rpc(fmt.Sprintf(establishStream, `<stream-xpath-filter>/ietf-netconf-notifications:netconf-session-start</stream-xpath-filter>`, ""))
	mustNoRPCError(t, reply, raw)

	c, err := dialTestNetconfSSH(t, sshAddr, USERNAME, ssh.Password("secret"))
	if err != nil {
		t.Fatalf("SSH login: %v", err)
	}
	if childText(c.hello, nsNetconfBase, "session-id") == "" {
		t.Fatal("no session-id in the hello over SSH")
	}
	reply, raw = c.rpc(`<get><filter type="subtree"><interfaces xmlns="` + nsIETFInterfaces + `"/></filter></get>`)
	mustNoRPCError(t, reply, raw)
	if got := len(interfacesIn(reply.Child(nsNetconfBase, "data"))); got != 2 {
		t.Fatalf("%d interfaces over SSH: %s", got, raw)
	}
	n, raw := watcher.notification(5 * time.Second)
	start := n.Child(nsNetconfNotifications, "netconf-session-start")
	if start == nil || childText(start, nsNetconfNotifications, "username") != USERNAME {
		t.Fatalf("session-start does not carry the SSH login: %s", raw)
	}
	if mgr.GetNetconfStatus().SessionsActive != 2 {
		t.Errorf("sessions_active %d, want 2", mgr.GetNetconfStatus().SessionsActive)
	}
}

// TestNetconfSSHAuthentication covers each method, the failures and their
// counter.
func TestNetconfSSHAuthentication(t *testing.T) {
	key, authorized := newTestSSHKey(t)
	other, _ := newTestSSHKey(t)
	mgr, _, addr := startTestNetconfSSH(t, 1, NetconfSubsystemConfig{SSHUser: "netconf", SSHPassword: "secret", SSHAuthorizedKeys: authorized})
	for _, tc := range []struct {
		name string
		user string
		auth ssh.AuthMethod
		ok   bool
	}{
		{"password", "netconf", ssh.Password("secret"), true},
		{"keyboard-interactive", "netconf", keyboardInteractive("secret"), true},
		{"publickey", "netconf", ssh.PublicKeys(key), true},
		{"wrong password", "netconf", ssh.Password("nope"), false},
		{"wrong user", "admin", ssh.Password("secret"), false},
		{"key for the wrong user", "admin", ssh.PublicKeys(key), false},
		{"unlisted key", "netconf", ssh.PublicKeys(other), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := mgr.netconf.sshAuthFailures.Load()
			_, err := dialTestNetconfSSH(t, addr, tc.user, tc.auth)
			if (err == nil) != tc.ok {
				t.Fatalf("login: %v, want ok=%v", err, tc.ok)
			}
			if failed := mgr.netconf.sshAuthFailures.Load() > before; failed == tc.ok {
				t.Errorf("ssh_auth_failures moved=%v on a login that ok=%v", failed, tc.ok)
			}
		})
	}
	st := mgr.GetNetconfStatus()
	if fmt.Sprint(st.SSHAuthMethods) != "[password keyboard-interactive publickey]" || st.SSHUser != "netconf" {
		t.Errorf("status auth: user %q methods %v", st.SSHUser, st.SSHAuthMethods)
	}
}

func TestNetconfSSHKeysOnlyRefusesPasswords(t *testing.T) {
	key, authorized := newTestSSHKey(t)
	_, _, addr := startTestNetconfSSH(t, 1, NetconfSubsystemConfig{SSHAuthorizedKeys: authorized})
	if _, err := dialTestNetconfSSH(t, addr, USERNAME, ssh.Password(PASSWORD)); err == nil {
		t.Fatal("password accepted with password login disabled")
	}
	if _, err := dialTestNetconfSSH(t, addr, USERNAME, ssh.PublicKeys(key)); err != nil {
		t.Fatalf("key login: %v", err)
	}
}

// TestNetconfSSHHostKeyIsReported: the fingerprint in status is the key the
// client is shown, in the SHA256:<base64> form a host-key policy pins.
func TestNetconfSSHHostKeyIsReported(t *testing.T) {
	_, hostPEM := newTestSSHHostKeyPEM(t)
	mgr, _, addr := startTestNetconfSSH(t, 1, NetconfSubsystemConfig{SSHPassword: "secret", SSHHostKeyPEM: hostPEM})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var seen ssh.PublicKey
	conn, err := openTestSSH(raw, USERNAME, []ssh.AuthMethod{ssh.Password("secret")}, &seen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got, want := mgr.GetNetconfStatus().SSHHostKeyFingerprint, ssh.FingerprintSHA256(seen); got != want {
		t.Fatalf("ssh_host_key_fingerprint %q, client saw %q", got, want)
	}
	if ssh.FingerprintSHA256(seen) == ssh.FingerprintSHA256(testNetconfSSHSigner(t).PublicKey()) {
		t.Fatal("the shared key was presented, not -netconf-ssh-host-key")
	}
}

func newTestSSHHostKeyPEM(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(key)
	return signer, pem.EncodeToMemory(block)
}

// TestNetconfSSHServesOnlyTheSubsystem: a shell or exec is refused (the
// CLI has its own port), the netconf subsystem then works on another
// channel, and a second NETCONF channel on the connection is refused.
func TestNetconfSSHServesOnlyTheSubsystem(t *testing.T) {
	_, _, addr := startTestNetconfSSH(t, 1, NetconfSubsystemConfig{SSHPassword: "secret"})
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: USERNAME, Auth: []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey()}) //nolint:gosec // test server
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, try := range []func(*ssh.Session) error{
		func(s *ssh.Session) error { return s.Shell() },
		func(s *ssh.Session) error { return s.Start("show version") },
		func(s *ssh.Session) error { return s.RequestSubsystem("sftp") },
	} {
		s, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err := try(s); err == nil {
			t.Error("a non-NETCONF request was accepted")
		}
		_ = s.Close()
	}
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestSubsystem(netconfSSHSubsystem); err != nil {
		t.Fatalf("netconf subsystem after refused requests: %v", err)
	}
	if _, err := client.NewSession(); err == nil {
		t.Fatal("a second channel was accepted on a connection carrying a NETCONF session")
	}
}

// TestNetconfSSHConnWriteDeadline: a client that stops reading fills the
// channel window, and the write must still end at its deadline. The socket
// write deadline TLS relies on cannot see that block.
func TestNetconfSSHConnWriteDeadline(t *testing.T) {
	// Loopback TCP, not net.Pipe: an unbuffered pipe deadlocks the two
	// version banners SSH writes at once.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cliRaw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srvRaw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer srvRaw.Close()
	srvCfg := netconfSSHConfig(testNetconfSSHSigner(t), &netconfSSHAuth{user: "u", password: "p"}, nil)
	chC := make(chan ssh.Channel, 1)
	go func() {
		_, chans, reqs, err := ssh.NewServerConn(srvRaw, srvCfg)
		if err != nil {
			close(chC)
			return
		}
		go ssh.DiscardRequests(reqs)
		chC <- netconfSSHSubsystemChannel(chans)
	}()
	conn, err := openTestSSH(cliRaw, "u", []ssh.AuthMethod{ssh.Password("p")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = cliRaw.SetDeadline(time.Time{})
	defer conn.Close()
	sc := &netconfSSHConn{ch: <-chC, raw: srvRaw}
	_ = sc.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
	done := make(chan error, 1)
	go func() {
		chunk := make([]byte, 64<<10)
		for {
			if _, err := sc.Write(chunk); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("write ended without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a write blocked on the channel window outlived its deadline")
	}
}

// TestNetconfSSHReadDeadlineDisarms: clearing the read deadline must stop
// the timer, or the hello's 30 s bound would end every idle session.
func TestNetconfSSHReadDeadlineDisarms(t *testing.T) {
	_, _, addr := startTestNetconfSSH(t, 1, NetconfSubsystemConfig{SSHPassword: "secret"})
	c, err := dialTestNetconfSSH(t, addr, USERNAME, ssh.Password("secret"))
	if err != nil {
		t.Fatal(err)
	}
	sc := func() *netconfSSHConn {
		srv := manager.devices["test"].netconfServer
		srv.mu.Lock()
		defer srv.mu.Unlock()
		for _, s := range srv.sessions {
			return s.conn.(*netconfSSHConn)
		}
		return nil
	}()
	_ = sc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_ = sc.SetReadDeadline(time.Time{})
	time.Sleep(300 * time.Millisecond)
	reply, raw := c.rpc(`<get-config><source><running/></source></get-config>`)
	mustNoRPCError(t, reply, raw)
}

func TestNetconfSSHConfigIsValidatedAtStart(t *testing.T) {
	_, hostPEM := newTestSSHHostKeyPEM(t)
	for name, cfg := range map[string]NetconfSubsystemConfig{
		"ssh settings without ssh":    {SSHAuthorizedKeys: []byte("x")},
		"host key without ssh":        {SSHHostKeyPEM: hostPEM},
		"no way to log in":            {SSHEnabled: true},
		"bad authorized keys":         {SSHEnabled: true, SSHAuthorizedKeys: []byte("not a key")},
		"bad host key":                {SSHEnabled: true, SSHPassword: "p", SSHHostKeyPEM: []byte("not a key")},
		"bad port":                    {SSHEnabled: true, SSHPassword: "p", SSHPort: 70000},
		"transport without call home": {CallHomeTransport: "ssh"},
		"unknown call home transport": {CallHome: "h", CallHomeTransport: "quic"},
		"ssh call home with no login": {CallHome: "h", CallHomeTransport: "ssh"},
	} {
		mgr := &SimulatorManager{sharedTLSCert: generateTestTLSCert(t), sharedSSHSigner: testNetconfSSHSigner(t)}
		cfg.Enabled = true
		if err := mgr.StartNetconfSubsystem(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The flags' defaults (the CLI login) are not "settings" on their own.
	mgr := &SimulatorManager{sharedTLSCert: generateTestTLSCert(t), sharedSSHSigner: testNetconfSSHSigner(t)}
	if err := mgr.StartNetconfSubsystem(NetconfSubsystemConfig{Enabled: true, SSHUser: USERNAME, SSHPassword: PASSWORD}); err != nil {
		t.Errorf("TLS only with the default SSH flags: %v", err)
	}
	if mgr.GetNetconfStatus().SSHHostKeyFingerprint != "" {
		t.Error("SSH reported in status with SSH off")
	}
	mgr = &SimulatorManager{sharedTLSCert: generateTestTLSCert(t), sharedSSHSigner: testNetconfSSHSigner(t)}
	if err := mgr.StartNetconfSubsystem(NetconfSubsystemConfig{Enabled: true, CallHome: "h", CallHomeTransport: "ssh", SSHPassword: "p"}); err != nil {
		t.Fatal(err)
	}
	if st := mgr.GetNetconfStatus(); st.CallHome != "h:4334" || st.CallHomeTransport != "ssh" || st.SSHPort != 0 {
		t.Errorf("SSH Call Home status: callhome %q transport %q ssh_port %d", st.CallHome, st.CallHomeTransport, st.SSHPort)
	}
}

// TestNetconfSSHCallHome: with -netconf-callhome-transport ssh the device
// dials, is the SSH server on the connection (RFC 8071 §3.1), and the
// configured subscriptions open the session as they do over TLS.
func TestNetconfSSHCallHome(t *testing.T) {
	col := newTestCallHomeCollector(t)
	mgr, _, _ := startTestNetconf(t, 1, NetconfSubsystemConfig{
		CallHome: col.addr(), CallHomeTransport: "ssh", CallHomeSubscriptions: "stream", SSHPassword: "secret",
	})
	if mgr.devices["test"].netconfServer.sshLn != nil {
		t.Fatal("SSH Call Home opened an SSH listener without -netconf-ssh")
	}
	raw := col.accept(t, 5*time.Second)
	var seen ssh.PublicKey
	conn, err := openTestSSH(raw, USERNAME, []ssh.AuthMethod{ssh.Password("secret")}, &seen)
	if err != nil {
		t.Fatalf("SSH Call Home session: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if ssh.FingerprintSHA256(seen) != mgr.GetNetconfStatus().SSHHostKeyFingerprint {
		t.Fatal("the Call Home host key is not the one status reports")
	}
	c, err := helloTestNetconf(t, conn, true)
	if err != nil {
		t.Fatal(err)
	}
	first := configuredStarted(t, c, "1")
	if first["1"].Local != "subscription-started" {
		t.Fatalf("the SSH Call Home session opened with <%s>", first["1"].Local)
	}
	reply, raw2 := c.rpc(`<get-config><source><running/></source></get-config>`)
	mustNoRPCError(t, reply, raw2)
	if got := *mgr.GetNetconfStatus().CallHomeConnected; got != 1 {
		t.Errorf("callhome_connected %d", got)
	}
}
