/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// NETCONF over SSH (RFC 6242): the netconf subsystem of an SSH session.
// After the subsystem starts, the session is the one TLS carries; only the
// transport and the source of the username differ. nl6 is the SSH server
// both on its listener (port 830) and on SSH Call Home (RFC 8071 §3.1).

// netconfSSHDefaultPort is the IANA port for NETCONF over SSH (RFC 6242 §3).
const netconfSSHDefaultPort = 830

// netconfSSHSubsystem is the subsystem name RFC 6242 §3 registers.
const netconfSSHSubsystem = "netconf"

// netconfSSHAuth is the configured login. A key in keys authenticates the
// user as a password does; either may be absent, not both.
type netconfSSHAuth struct {
	user     string
	password string
	keys     map[string]bool // ssh.PublicKey.Marshal() of each authorized key
}

func (a *netconfSSHAuth) userOK(c ssh.ConnMetadata) bool {
	return subtle.ConstantTimeCompare([]byte(c.User()), []byte(a.user)) == 1
}

func (a *netconfSSHAuth) passwordOK(c ssh.ConnMetadata, pass []byte) bool {
	ok := a.userOK(c)
	return a.password != "" && subtle.ConstantTimeCompare(pass, []byte(a.password)) == 1 && ok
}

var errNetconfSSHAuth = errors.New("netconf: SSH authentication failed")

// netconfSSHConfig builds the server configuration. Password, keyboard-
// interactive (a password prompt, which some clients try first) and public
// key authentication are offered according to what is configured.
func netconfSSHConfig(signer ssh.Signer, auth *netconfSSHAuth, onAuthFailure func()) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-nl6-netconf",
		// MaxAuthTries bounds a client that walks a key agent's keys.
		MaxAuthTries: 6,
		AuthLogCallback: func(_ ssh.ConnMetadata, method string, err error) {
			if err != nil && method != "none" && onAuthFailure != nil {
				onAuthFailure()
			}
		},
	}
	if auth.password != "" {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if auth.passwordOK(c, pass) {
				return nil, nil
			}
			return nil, errNetconfSSHAuth
		}
		cfg.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := ch("", "", []string{"Password: "}, []bool{false})
			if err == nil && len(answers) == 1 && auth.passwordOK(c, []byte(answers[0])) {
				return nil, nil
			}
			return nil, errNetconfSSHAuth
		}
	}
	if len(auth.keys) > 0 {
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if auth.userOK(c) && auth.keys[string(key.Marshal())] {
				return nil, nil
			}
			return nil, errNetconfSSHAuth
		}
	}
	cfg.AddHostKey(signer)
	return cfg
}

// parseNetconfAuthorizedKeys reads an OpenSSH authorized_keys file. Options
// and comments are accepted and ignored.
func parseNetconfAuthorizedKeys(data []byte) (map[string]bool, error) {
	keys := map[string]bool{}
	rest := bytes.TrimSpace(data)
	for len(rest) > 0 {
		key, _, _, r, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return nil, fmt.Errorf("netconf: -netconf-ssh-authorized-keys: %v", err)
		}
		keys[string(key.Marshal())] = true
		rest = bytes.TrimSpace(r)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("netconf: -netconf-ssh-authorized-keys holds no key")
	}
	return keys, nil
}

// serveSSH is the server side of RFC 6242 on raw, which the device either
// accepted or dialled for Call Home. It runs the SSH handshake and
// authentication, waits for a session channel requesting the netconf
// subsystem, and serves the NETCONF session on that channel. One NETCONF
// session per SSH connection: further channels are refused. It reports
// whether a session ran.
func (srv *netconfServer) serveSSH(raw net.Conn, callHome bool) bool {
	nc := &srv.mgr.netconf
	defer raw.Close()
	// One bound for the SSH handshake, authentication and the subsystem
	// request; the hello then has the session's own.
	_ = raw.SetDeadline(time.Now().Add(netconfHelloTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(raw, nc.sshConfig)
	if err != nil {
		if !srv.isClosed() {
			nc.sshHandshakeFailures.Add(1)
			nc.logFirstSSHError(srv.dev, raw.RemoteAddr(), err)
		}
		return false
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs) // keepalives are answered with a failure, which OpenSSH and MINA accept

	ch := netconfSSHSubsystemChannel(chans)
	if ch == nil {
		return false
	}
	go func() {
		for newCh := range chans {
			_ = newCh.Reject(ssh.Prohibited, "nl6 runs one NETCONF session per SSH connection")
		}
	}()
	_ = raw.SetDeadline(time.Time{})
	return srv.runSession(&netconfSSHConn{ch: ch, raw: raw}, raw.RemoteAddr(), sconn.User(), callHome)
}

// netconfSSHSubsystemChannel accepts session channels until one asks for
// the netconf subsystem, which it returns. Any other request on a channel
// (shell, exec, pty-req, env) is refused: this listener serves NETCONF
// only, and the device's CLI is on its own SSH port. nil when the
// connection ends first.
func netconfSSHSubsystemChannel(chans <-chan ssh.NewChannel) ssh.Channel {
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are served")
			continue
		}
		ch, creqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		for req := range creqs {
			var sub struct{ Name string }
			if req.Type == "subsystem" && ssh.Unmarshal(req.Payload, &sub) == nil && sub.Name == netconfSSHSubsystem {
				_ = req.Reply(true, nil)
				go ssh.DiscardRequests(creqs)
				return ch
			}
			_ = req.Reply(false, nil)
		}
		_ = ch.Close()
	}
	return nil
}

// netconfSSHConn is the netconf channel as a session transport. A channel
// has no deadlines of its own, and a write can block on the client's flow
// control window rather than on the socket, so a deadline is enforced by
// closing the SSH connection when it passes, as an expired TLS deadline
// ends that session too.
type netconfSSHConn struct {
	ch  ssh.Channel
	raw net.Conn

	mu      sync.Mutex
	readT   *time.Timer
	writeBy time.Time
}

func (c *netconfSSHConn) Read(p []byte) (int, error) { return c.ch.Read(p) }

func (c *netconfSSHConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	by := c.writeBy
	c.mu.Unlock()
	if !by.IsZero() {
		t := time.AfterFunc(time.Until(by), func() { _ = c.raw.Close() })
		defer t.Stop()
	}
	return c.ch.Write(p)
}

// Close ends the channel and the SSH connection under it: the connection
// carries this session only.
func (c *netconfSSHConn) Close() error {
	_ = c.ch.Close()
	return c.raw.Close()
}

// SetReadDeadline arms a timer that closes the connection at t; the zero
// time disarms it.
func (c *netconfSSHConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readT != nil {
		c.readT.Stop()
		c.readT = nil
	}
	if !t.IsZero() {
		c.readT = time.AfterFunc(time.Until(t), func() { _ = c.raw.Close() })
	}
	return nil
}

// SetWriteDeadline applies to the writes that follow, each of which is
// bounded by it while it runs.
func (c *netconfSSHConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeBy = t
	c.mu.Unlock()
	return nil
}
