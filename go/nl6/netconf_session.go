/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// netconfHelloTimeout bounds the TLS handshake plus the client's hello.
	// A client that connects and says nothing holds a goroutine and a slot
	// of the per-device session cap, so this is the slowloris bound.
	netconfHelloTimeout = 30 * time.Second
	// netconfWriteTimeout bounds one framed write. A write that times out
	// leaves a partial frame on the wire, which no later write can repair,
	// so the session is closed rather than retried.
	netconfWriteTimeout = 10 * time.Second
	// netconfMaxMessageBytes caps one inbound message. Clients send RPCs
	// and filters, not data, so this is generous.
	netconfMaxMessageBytes = 1 << 20
	// netconfMaxSubscriptionsPerSession bounds the push work one session can
	// start. RFC 8639 answers the excess with insufficient-resources.
	netconfMaxSubscriptionsPerSession = 8
)

// netconfServerCapabilities is the server's hello. Modules are announced by
// the YANG library; RFC 7950 §5.6.4 lists only the implemented YANG 1.0
// modules in the hello as well. :interleave is RFC 8640's requirement for a
// publisher that takes RPCs on a session carrying subscriptions, which nl6
// does.
var netconfServerCapabilities = func() []string {
	caps := []string{
		"urn:ietf:params:netconf:base:1.0",
		"urn:ietf:params:netconf:base:1.1",
		"urn:ietf:params:netconf:capability:interleave:1.0",
		"urn:ietf:params:netconf:capability:notification:1.0",
		"urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&content-id=" + netconfLibraryContentID,
	}
	for _, m := range netconfModules {
		if !m.YANG10 || m.ImportOnly {
			continue
		}
		c := m.Namespace + "?module=" + m.Name + "&revision=" + m.Revision
		if len(m.Features) > 0 {
			c += "&features=" + strings.Join(m.Features, ",")
		}
		caps = append(caps, c)
	}
	return caps
}()

// netconfRPCError is one rpc-error (RFC 6241 §4.3).
type netconfRPCError struct {
	Type    string // transport | rpc | protocol | application
	Tag     string
	AppTag  string
	Message string
	Info    string // rendered XML for error-info
}

func (e *netconfRPCError) Error() string { return e.Tag + ": " + e.Message }

func netconfErr(typ, tag, format string, args ...any) *netconfRPCError {
	return &netconfRPCError{Type: typ, Tag: tag, Message: fmt.Sprintf(format, args...)}
}

// netconfBadElement is an error-info naming the offending element.
func netconfBadElement(name string) string {
	return "<bad-element>" + xmlEscapeString(name) + "</bad-element>"
}

func (e *netconfRPCError) write(b *bytes.Buffer) {
	b.WriteString("<rpc-error><error-type>")
	b.WriteString(e.Type)
	b.WriteString("</error-type><error-tag>")
	b.WriteString(e.Tag)
	b.WriteString("</error-tag><error-severity>error</error-severity>")
	if e.AppTag != "" {
		b.WriteString("<error-app-tag>")
		b.WriteString(xmlEscapeString(e.AppTag))
		b.WriteString("</error-app-tag>")
	}
	if e.Message != "" {
		b.WriteString(`<error-message xml:lang="en">`)
		b.WriteString(xmlEscapeString(e.Message))
		b.WriteString("</error-message>")
	}
	if e.Info != "" {
		b.WriteString("<error-info>")
		b.WriteString(e.Info)
		b.WriteString("</error-info>")
	}
	b.WriteString("</rpc-error>")
}

// netconfRPCResult is what an operation hands back to the dispatcher.
type netconfRPCResult struct {
	body  string // reply content: "<ok/>", "<data>…</data>", "<id>…</id>"
	err   *netconfRPCError
	after func() // runs once the reply is on the wire
	close bool   // close the session after the reply
}

var netconfOK = netconfRPCResult{body: "<ok/>"}

// netconfSession is one NETCONF session on one TLS connection.
type netconfSession struct {
	id   uint32
	srv  *netconfServer
	conn net.Conn
	rd   *netconfReader
	// chunked is set once, during the hello exchange, before any goroutine
	// other than the session's own can write.
	chunked bool
	wmu     sync.Mutex

	subsMu sync.Mutex
	subs   map[uint32]*netconfSubscription

	// user and source identify the session in RFC 6470 session events: the
	// client certificate's common name, and the peer address.
	user, source string
	helloDone    bool // the session-start was recorded, so an end is owed

	// endReason and killedBy describe how the session ended, for its
	// netconf-session-end. Written before close runs, read inside it.
	endMu     sync.Mutex
	endReason string
	killedBy  uint32

	done      chan struct{}
	closeOnce sync.Once
}

// closeWith records why the session ends and closes it. The first reason
// wins: a kill-session racing a read error still reports killed.
func (s *netconfSession) closeWith(reason string, killedBy uint32) {
	s.endMu.Lock()
	if s.endReason == "" {
		s.endReason, s.killedBy = reason, killedBy
	}
	s.endMu.Unlock()
	s.close()
}

// run serves the session until the connection ends. A panic while serving
// it closes this session only: the session goroutine is not under net/http
// or gRPC, so nothing else would recover it, and an unrecovered panic ends
// the simulator and every device in it.
func (s *netconfSession) run() {
	defer s.close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("netconf: device %s session %d: recovered from panic: %v", s.srv.dev.IP, s.id, r)
		}
	}()
	if err := s.hello(); err != nil {
		s.srv.mgr.netconf.helloFailures.Add(1)
		s.srv.mgr.netconf.logFirstHelloError(s.srv.dev, err)
		return
	}
	s.helloDone = true
	s.srv.events.sessionEvent(netconfEvent{kind: netconfEventSessionStart, sessionID: s.id, user: s.user, source: s.source})
	for {
		msg, err := s.rd.ReadMessage()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !s.isClosed() {
				log.Printf("netconf: device %s session %d: %v", s.srv.dev.IP, s.id, err)
			}
			return
		}
		if !s.handle(msg) {
			return
		}
	}
}

// hello sends the server hello and reads the client's (RFC 6241 §8.1).
func (s *netconfSession) hello() error {
	_ = s.conn.SetReadDeadline(time.Now().Add(netconfHelloTimeout))
	var b bytes.Buffer
	b.WriteString(`<hello xmlns="` + nsNetconfBase + `"><capabilities>`)
	for _, c := range netconfServerCapabilities {
		b.WriteString("<capability>")
		b.WriteString(xmlEscapeString(c))
		b.WriteString("</capability>")
	}
	b.WriteString("</capabilities><session-id>")
	b.WriteString(strconv.FormatUint(uint64(s.id), 10))
	b.WriteString("</session-id></hello>")
	if err := s.send(b.Bytes()); err != nil {
		return err
	}
	msg, err := s.rd.ReadMessage()
	if err != nil {
		return fmt.Errorf("reading client hello: %w", err)
	}
	root, err := parseNetconfXML(msg)
	if err != nil {
		return fmt.Errorf("client hello is not XML: %w", err)
	}
	if root.Space != nsNetconfBase || root.Local != "hello" {
		return fmt.Errorf("first client message is <%s>, not a hello", root.Local)
	}
	if root.Child(nsNetconfBase, "session-id") != nil {
		return fmt.Errorf("client hello carries a session-id")
	}
	var base10, base11 bool
	if caps := root.Child(nsNetconfBase, "capabilities"); caps != nil {
		for _, c := range caps.Children {
			switch c.Text {
			case "urn:ietf:params:netconf:base:1.0":
				base10 = true
			case "urn:ietf:params:netconf:base:1.1":
				base11 = true
			}
		}
	}
	if !base10 && !base11 {
		return fmt.Errorf("client hello advertises no common base capability")
	}
	s.chunked = base11
	s.rd.chunked = base11
	_ = s.conn.SetReadDeadline(time.Time{})
	return nil
}

// send writes one message, framed for the session. A failed write closes
// the session: the frame may be partly written.
func (s *netconfSession) send(msg []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.isClosed() {
		return net.ErrClosed
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(netconfWriteTimeout))
	if _, err := s.conn.Write(frameNetconfMessage(msg, s.chunked)); err != nil {
		go s.close()
		return err
	}
	return nil
}

// sendNotification wraps body in an RFC 5277 notification envelope.
func (s *netconfSession) sendNotification(eventTime time.Time, body string) error {
	msg := `<notification xmlns="` + nsNetconfNotif + `"><eventTime>` + netconfDateTime(eventTime) +
		`</eventTime>` + body + `</notification>`
	err := s.send([]byte(msg))
	if err != nil {
		s.srv.mgr.netconf.notificationWriteFailures.Add(1)
	}
	return err
}

func (s *netconfSession) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// close ends the session: its subscriptions stop, its lock is released and
// the connection closes. Idempotent.
func (s *netconfSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.conn.Close()
		s.subsMu.Lock()
		subs := s.subs
		s.subs = nil
		s.subsMu.Unlock()
		for _, sub := range subs {
			sub.stop()
		}
		s.srv.removeSession(s)
		if s.helloDone {
			s.endMu.Lock()
			reason, killer := s.endReason, s.killedBy
			s.endMu.Unlock()
			if reason == "" {
				reason = "dropped"
			}
			s.srv.events.sessionEvent(netconfEvent{kind: netconfEventSessionEnd, sessionID: s.id,
				user: s.user, source: s.source, reason: reason, killedBy: killer})
		}
	})
}

// handle parses and answers one message. It returns false when the session
// should end.
func (s *netconfSession) handle(msg []byte) bool {
	nc := &s.srv.mgr.netconf
	root, err := parseNetconfXML(msg)
	if err != nil {
		nc.rpcErrors.Add(1)
		return s.sendReply(nil, netconfRPCResult{err: netconfErr("rpc", "malformed-message", "%v", err)}) == nil
	}
	if root.Space != nsNetconfBase || root.Local != "rpc" {
		nc.rpcErrors.Add(1)
		return s.sendReply(nil, netconfRPCResult{err: netconfErr("rpc", "unknown-element", "expected <rpc>, got <%s>", root.Local)}) == nil
	}
	nc.rpcs.Add(1)
	var res netconfRPCResult
	if _, ok := root.Attr("message-id"); !ok {
		res.err = netconfErr("rpc", "missing-attribute", "the rpc element has no message-id")
		res.err.Info = "<bad-attribute>message-id</bad-attribute><bad-element>rpc</bad-element>"
	} else if len(root.Children) != 1 {
		res.err = netconfErr("protocol", "malformed-message", "an rpc carries exactly one operation, got %d", len(root.Children))
	} else {
		res = s.dispatch(root.Children[0])
	}
	if res.err != nil {
		nc.rpcErrors.Add(1)
	}
	if err := s.sendReply(root, res); err != nil {
		return false
	}
	if res.after != nil {
		res.after()
	}
	if res.close {
		s.closeWith("closed", 0)
	}
	return !res.close
}

// sendReply writes an rpc-reply, echoing the rpc's attributes as RFC 6241
// §4.2 requires. rpc is nil when the request could not be parsed, in which
// case the reply carries no message-id.
func (s *netconfSession) sendReply(rpc *xmlElem, res netconfRPCResult) error {
	var b bytes.Buffer
	b.WriteString(`<rpc-reply xmlns="` + nsNetconfBase + `"`)
	if rpc != nil {
		n := 0
		for _, a := range rpc.Attrs {
			b.WriteByte(' ')
			if a.Name.Space != "" {
				n++
				p := "a" + strconv.Itoa(n)
				b.WriteString("xmlns:" + p + `="`)
				xmlEscapeAttr(&b, a.Name.Space)
				b.WriteString(`" ` + p + ":")
			}
			b.WriteString(a.Name.Local + `="`)
			xmlEscapeAttr(&b, a.Value)
			b.WriteByte('"')
		}
	}
	b.WriteByte('>')
	if res.err != nil {
		res.err.write(&b)
	} else {
		b.WriteString(res.body)
	}
	b.WriteString("</rpc-reply>")
	return s.send(b.Bytes())
}

// dispatch runs one operation.
func (s *netconfSession) dispatch(op *xmlElem) netconfRPCResult {
	switch op.Space {
	case nsNetconfBase:
		switch op.Local {
		case "get":
			return s.opGet(op)
		case "get-config":
			return s.opGetConfig(op)
		case "lock":
			return s.opLock(op, true)
		case "unlock":
			return s.opLock(op, false)
		case "close-session":
			return netconfRPCResult{body: "<ok/>", close: true}
		case "kill-session":
			return s.opKillSession(op)
		case "edit-config", "copy-config", "delete-config", "validate", "commit", "discard-changes", "cancel-commit":
			return netconfRPCResult{err: netconfErr("protocol", "operation-not-supported",
				"nl6 serves read-only data; %s is not supported", op.Local)}
		}
	case nsNetconfNMDA:
		if op.Local == "get-data" {
			return s.opGetData(op)
		}
	case nsNetconfMonitoring:
		if op.Local == "get-schema" {
			return s.opGetSchema(op)
		}
	case nsSubscribedNotif:
		switch op.Local {
		case "establish-subscription":
			return s.opEstablishSubscription(op)
		case "delete-subscription":
			return s.opDeleteSubscription(op)
		}
	case nsNetconfNotif:
		if op.Local == "create-subscription" {
			return s.opCreateSubscription(op)
		}
	}
	return netconfRPCResult{err: netconfErr("protocol", "operation-not-supported", "operation %s (%s) is not supported", op.Local, op.Space)}
}

// netconfFilterFrom reads an RFC 6241 <filter> element. filtered is false
// when there is none, which selects everything.
func netconfFilterFrom(f *xmlElem) (filter []*filterNode, filtered bool, rerr *netconfRPCError) {
	if f == nil {
		return nil, false, nil
	}
	typ, _ := f.Attr("type")
	switch typ {
	case "", "subtree":
		return subtreeFilterFromXML(f.Children), true, nil
	case "xpath":
		sel, ok := f.Attr("select")
		if !ok {
			e := netconfErr("protocol", "missing-attribute", "an xpath filter needs a select attribute")
			e.Info = "<bad-attribute>select</bad-attribute><bad-element>filter</bad-element>"
			return nil, false, e
		}
		nodes, err := xpathToSubtreeFilter(sel, f.Scope)
		if err != nil {
			return nil, false, netconfErr("application", "invalid-value", "%v", err)
		}
		return nodes, true, nil
	}
	e := netconfErr("protocol", "bad-attribute", "filter type %q is not supported", typ)
	e.Info = "<bad-attribute>type</bad-attribute><bad-element>filter</bad-element>"
	return nil, false, e
}

func (s *netconfSession) opGet(op *xmlElem) netconfRPCResult {
	filter, filtered, rerr := netconfFilterFrom(op.Child(nsNetconfBase, "filter"))
	if rerr != nil {
		return netconfRPCResult{err: rerr}
	}
	return s.dataReply("", s.srv.datastore(netconfOperational, time.Now()), filter, filtered)
}

func (s *netconfSession) opGetConfig(op *xmlElem) netconfRPCResult {
	src := op.Child(nsNetconfBase, "source")
	if src == nil || len(src.Children) != 1 {
		e := netconfErr("protocol", "missing-element", "get-config needs a source")
		e.Info = netconfBadElement("source")
		return netconfRPCResult{err: e}
	}
	if ds := src.Children[0]; ds.Space != nsNetconfBase || ds.Local != "running" {
		return netconfRPCResult{err: netconfErr("protocol", "invalid-value", "only the running datastore is served, not %s", ds.Local)}
	}
	filter, filtered, rerr := netconfFilterFrom(op.Child(nsNetconfBase, "filter"))
	if rerr != nil {
		return netconfRPCResult{err: rerr}
	}
	return s.dataReply("", s.srv.datastore(netconfRunning, time.Now()), filter, filtered)
}

// opGetData is RFC 8526 get-data.
func (s *netconfSession) opGetData(op *xmlElem) netconfRPCResult {
	var ds netconfDatastoreName
	var filter []*filterNode
	var filtered bool
	configFilter := "" // "", "true" or "false"
	for _, c := range op.Children {
		if c.Space != nsNetconfNMDA {
			return netconfRPCResult{err: netconfUnknownElement(c)}
		}
		switch c.Local {
		case "datastore":
			d, rerr := netconfParseDatastore(c, "invalid-value")
			if rerr != nil {
				return netconfRPCResult{err: rerr}
			}
			ds = d
		case "subtree-filter":
			filter, filtered = subtreeFilterFromXML(c.Children), true
		case "xpath-filter":
			nodes, err := xpathToSubtreeFilter(c.Text, c.Scope)
			if err != nil {
				return netconfRPCResult{err: netconfErr("application", "invalid-value", "%v", err)}
			}
			filter, filtered = nodes, true
		case "config-filter":
			if c.Text != "true" && c.Text != "false" {
				return netconfRPCResult{err: netconfErr("application", "invalid-value", "config-filter %q is not a boolean", c.Text)}
			}
			configFilter = c.Text
		case "max-depth":
			if c.Text != "unbounded" {
				return netconfRPCResult{err: netconfErr("application", "invalid-value", "nl6 supports only max-depth unbounded")}
			}
		default:
			return netconfRPCResult{err: netconfErr("protocol", "operation-not-supported",
				"get-data parameter %s is not supported", c.Local)}
		}
	}
	if ds == "" {
		e := netconfErr("protocol", "missing-element", "get-data needs a datastore")
		e.Info = netconfBadElement("datastore")
		return netconfRPCResult{err: e}
	}
	return s.dataReply(nsNetconfNMDA, netconfConfigFilter(s.srv.datastore(ds, time.Now()), configFilter), filter, filtered)
}

func netconfUnknownElement(c *xmlElem) *netconfRPCError {
	e := netconfErr("protocol", "unknown-element", "unexpected element %s (%s)", c.Local, c.Space)
	e.Info = netconfBadElement(c.Local)
	return e
}

// dataReply renders <data>; dataNS is the namespace of the data element
// (empty for the base protocol's).
func (s *netconfSession) dataReply(dataNS string, nodes []*ncNode, filter []*filterNode, filtered bool) netconfRPCResult {
	nodes = applyNetconfFilter(nodes, filter, filtered)
	var b bytes.Buffer
	parentNS := nsNetconfBase
	if dataNS != "" {
		b.WriteString(`<data xmlns="` + dataNS + `">`)
		parentNS = dataNS
	} else {
		b.WriteString("<data>")
	}
	writeNetconfNodes(&b, nodes, parentNS)
	b.WriteString("</data>")
	return netconfRPCResult{body: b.String()}
}

// netconfParseDatastore resolves an ietf-datastores identityref. tag is the
// error-tag for a datastore nl6 does not serve.
func netconfParseDatastore(e *xmlElem, tag string) (netconfDatastoreName, *netconfRPCError) {
	prefix, local := "", e.Text
	if i := strings.IndexByte(e.Text, ':'); i >= 0 {
		prefix, local = e.Text[:i], e.Text[i+1:]
	}
	ns := e.Scope[prefix]
	if prefix == "ietf-datastores" {
		ns = nsDatastores
	}
	if ns != nsDatastores {
		return "", netconfErr("application", "invalid-value", "datastore %q is not an ietf-datastores identity", e.Text)
	}
	switch netconfDatastoreName(local) {
	case netconfRunning, netconfOperational:
		return netconfDatastoreName(local), nil
	}
	return "", netconfErr("application", tag, "nl6 serves the running and operational datastores, not %s", local)
}

func (s *netconfSession) opLock(op *xmlElem, lock bool) netconfRPCResult {
	target := op.Child(nsNetconfBase, "target")
	if target == nil || target.Child(nsNetconfBase, "running") == nil {
		return netconfRPCResult{err: netconfErr("protocol", "invalid-value", "only the running datastore can be locked")}
	}
	if lock {
		if holder := s.srv.lockRunning(s.id); holder != 0 {
			e := netconfErr("protocol", "lock-denied", "the running datastore is locked by session %d", holder)
			e.Info = "<session-id>" + strconv.FormatUint(uint64(holder), 10) + "</session-id>"
			return netconfRPCResult{err: e}
		}
		return netconfOK
	}
	if !s.srv.unlockRunning(s.id) {
		return netconfRPCResult{err: netconfErr("protocol", "operation-failed", "this session does not hold the lock")}
	}
	return netconfOK
}

func (s *netconfSession) opKillSession(op *xmlElem) netconfRPCResult {
	idEl := op.Child(nsNetconfBase, "session-id")
	if idEl == nil {
		e := netconfErr("protocol", "missing-element", "kill-session needs a session-id")
		e.Info = netconfBadElement("session-id")
		return netconfRPCResult{err: e}
	}
	id, err := strconv.ParseUint(idEl.Text, 10, 32)
	if err != nil || uint32(id) == s.id {
		return netconfRPCResult{err: netconfErr("protocol", "invalid-value", "session-id %q is not another session", idEl.Text)}
	}
	victim := s.srv.session(uint32(id))
	if victim == nil {
		return netconfRPCResult{err: netconfErr("protocol", "invalid-value", "no session %d", id)}
	}
	victim.closeWith("killed", s.id)
	return netconfOK
}
