/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dynamic YANG-Push subscriptions (RFC 8639 establish-subscription carrying
// the RFC 8641 datastore augmentations). nl6 publishes no event streams, so a
// stream subscription is refused with stream-unavailable rather than
// accepted and left silent.
//
// On-change reports what the interface state engine moves: admin-status,
// oper-status, enabled and last-change. Statistics change continuously and
// are not on-change notifiable here, as on most devices; a collector wanting
// counters subscribes periodically.

// netconfMinPeriod is the shortest periodic interval accepted. Shorter is
// refused with period-unsupported, never clamped: a clamped period is the
// accepted-echoed-ignored failure nl6#445 removed elsewhere.
const netconfMinPeriod = time.Second

// netconfOnChangeBuffer is the depth of a subscription's state listener
// channel; the engine drops the oldest event when it is full.
const netconfOnChangeBuffer = 64

// netconfChangeTypes are RFC 8641's change types for excluded-change.
var netconfChangeTypes = map[string]bool{"create": true, "delete": true, "insert": true, "move": true, "replace": true}

type netconfDatastoreName string

const (
	netconfRunning     netconfDatastoreName = "running"
	netconfOperational netconfDatastoreName = "operational"
)

// netconfSubscription is one dynamic subscription on one session.
type netconfSubscription struct {
	id        uint32
	sess      *netconfSession
	datastore netconfDatastoreName
	filter    []*filterNode
	filtered  bool

	periodic bool
	period   time.Duration
	anchor   time.Time // zero when absent

	dampening   time.Duration
	syncOnStart bool
	excluded    map[string]bool

	stopTime time.Time // zero when absent

	mu      sync.Mutex // guards stopped and the listener registration
	stopped bool
	events  chan StateChange
	state   *InterfaceState // the engine events is registered on, if any
	quit    chan struct{}

	patchSeq uint64 // owned by the run goroutine
}

func netconfSubError(appTag, format string, args ...any) netconfRPCResult {
	e := netconfErr("application", "invalid-value", format, args...)
	e.AppTag = appTag
	return netconfRPCResult{err: e}
}

// parseCentiseconds reads a yp:centiseconds (uint32) value.
func parseCentiseconds(e *xmlElem) (time.Duration, bool) {
	v, err := strconv.ParseUint(e.Text, 10, 32)
	if err != nil {
		return 0, false
	}
	return time.Duration(v) * 10 * time.Millisecond, true
}

func (s *netconfSession) opEstablishSubscription(op *xmlElem) netconfRPCResult {
	sub := &netconfSubscription{sess: s, syncOnStart: true, excluded: map[string]bool{}}
	var haveTrigger bool
	for _, c := range op.Children {
		switch {
		case c.Space == nsSubscribedNotif && (c.Local == "stream" || c.Local == "stream-subtree-filter" ||
			c.Local == "stream-xpath-filter" || c.Local == "stream-filter-name" || c.Local == "replay-start-time"):
			return netconfSubError("ietf-subscribed-notifications:stream-unavailable",
				"nl6 publishes no event streams; subscribe to a datastore (RFC 8641)")
		case c.Space == nsSubscribedNotif && c.Local == "stop-time":
			t, err := time.Parse(time.RFC3339Nano, c.Text)
			if err != nil {
				return netconfRPCResult{err: netconfErr("application", "invalid-value", "stop-time %q is not a date-and-time", c.Text)}
			}
			if !t.After(time.Now()) {
				return netconfRPCResult{err: netconfErr("application", "invalid-value", "stop-time %s is not in the future", c.Text)}
			}
			sub.stopTime = t
		case c.Space == nsSubscribedNotif && c.Local == "encoding":
			if c.Text != "encode-xml" && !strings.HasSuffix(c.Text, ":encode-xml") {
				return netconfSubError("ietf-subscribed-notifications:encoding-unsupported",
					"nl6 encodes NETCONF notifications as XML only, not %s", c.Text)
			}
		case c.Space == nsYangPush && c.Local == "datastore":
			ds, rerr := netconfParseDatastore(c, "invalid-value")
			if rerr != nil {
				rerr.AppTag = "ietf-yang-push:datastore-not-subscribable"
				return netconfRPCResult{err: rerr}
			}
			sub.datastore = ds
		case c.Space == nsYangPush && c.Local == "datastore-subtree-filter":
			sub.filter, sub.filtered = subtreeFilterFromXML(c.Children), true
		case c.Space == nsYangPush && c.Local == "datastore-xpath-filter":
			nodes, err := xpathToSubtreeFilter(c.Text, c.Scope)
			if err != nil {
				return netconfSubError("ietf-subscribed-notifications:filter-unsupported", "%v", err)
			}
			sub.filter, sub.filtered = nodes, true
		case c.Space == nsYangPush && c.Local == "selection-filter-ref":
			return netconfSubError("ietf-subscribed-notifications:filter-unavailable",
				"nl6 has no configured selection filters to reference")
		case c.Space == nsYangPush && c.Local == "periodic":
			if rerr := sub.parsePeriodic(c); rerr != nil {
				return netconfRPCResult{err: rerr}
			}
			haveTrigger = true
		case c.Space == nsYangPush && c.Local == "on-change":
			if rerr := sub.parseOnChange(c); rerr != nil {
				return netconfRPCResult{err: rerr}
			}
			haveTrigger = true
		default:
			return netconfRPCResult{err: netconfUnknownElement(c)}
		}
	}
	if sub.datastore == "" {
		e := netconfErr("application", "missing-element", "establish-subscription needs a datastore (nl6 publishes no event streams)")
		e.Info = netconfBadElement("datastore")
		return netconfRPCResult{err: e}
	}
	if !haveTrigger {
		e := netconfErr("application", "missing-element", "a datastore subscription needs periodic or on-change")
		e.Info = netconfBadElement("update-trigger")
		return netconfRPCResult{err: e}
	}

	s.subsMu.Lock()
	if s.subs == nil { // the session closed under us
		s.subsMu.Unlock()
		return netconfRPCResult{err: netconfErr("application", "operation-failed", "session is closing")}
	}
	if len(s.subs) >= netconfMaxSubscriptionsPerSession {
		s.subsMu.Unlock()
		return netconfSubError("ietf-subscribed-notifications:insufficient-resources",
			"a session carries at most %d subscriptions", netconfMaxSubscriptionsPerSession)
	}
	sub.id = s.srv.mgr.netconf.nextSubscriptionID.Add(1)
	sub.quit = make(chan struct{})
	s.subs[sub.id] = sub
	s.subsMu.Unlock()
	s.srv.mgr.netconf.subscriptionsActive.Add(1)

	return netconfRPCResult{
		body:  `<id xmlns="` + nsSubscribedNotif + `">` + strconv.FormatUint(uint64(sub.id), 10) + `</id>`,
		after: sub.start, // after the reply, so the id is known before any update
	}
}

func (sub *netconfSubscription) parsePeriodic(c *xmlElem) *netconfRPCError {
	sub.periodic = true
	for _, p := range c.Children {
		switch {
		case p.Space == nsYangPush && p.Local == "period":
			d, ok := parseCentiseconds(p)
			if !ok {
				return netconfErr("application", "invalid-value", "period %q is not centiseconds", p.Text)
			}
			if d < netconfMinPeriod {
				e := netconfErr("application", "invalid-value", "period %s is below nl6's minimum of %s", d, netconfMinPeriod)
				e.AppTag = "ietf-yang-push:period-unsupported"
				return e
			}
			sub.period = d
		case p.Space == nsYangPush && p.Local == "anchor-time":
			t, err := time.Parse(time.RFC3339Nano, p.Text)
			if err != nil {
				return netconfErr("application", "invalid-value", "anchor-time %q is not a date-and-time", p.Text)
			}
			sub.anchor = t
		default:
			return netconfUnknownElement(p)
		}
	}
	if sub.period == 0 {
		e := netconfErr("application", "missing-element", "periodic needs a period")
		e.Info = netconfBadElement("period")
		return e
	}
	return nil
}

func (sub *netconfSubscription) parseOnChange(c *xmlElem) *netconfRPCError {
	for _, p := range c.Children {
		switch {
		case p.Space == nsYangPush && p.Local == "dampening-period":
			d, ok := parseCentiseconds(p)
			if !ok {
				return netconfErr("application", "invalid-value", "dampening-period %q is not centiseconds", p.Text)
			}
			sub.dampening = d
		case p.Space == nsYangPush && p.Local == "sync-on-start":
			switch p.Text {
			case "true":
				sub.syncOnStart = true
			case "false":
				sub.syncOnStart = false
			default:
				return netconfErr("application", "invalid-value", "sync-on-start %q is not a boolean", p.Text)
			}
		case p.Space == nsYangPush && p.Local == "excluded-change":
			if !netconfChangeTypes[p.Text] {
				return netconfErr("application", "invalid-value", "excluded-change %q is not a change type", p.Text)
			}
			sub.excluded[p.Text] = true
		default:
			return netconfUnknownElement(p)
		}
	}
	return nil
}

func (s *netconfSession) opDeleteSubscription(op *xmlElem) netconfRPCResult {
	idEl := op.Child(nsSubscribedNotif, "id")
	if idEl == nil {
		e := netconfErr("application", "missing-element", "delete-subscription needs an id")
		e.Info = netconfBadElement("id")
		return netconfRPCResult{err: e}
	}
	id, err := strconv.ParseUint(idEl.Text, 10, 32)
	s.subsMu.Lock()
	sub := s.subs[uint32(id)]
	if err == nil && sub != nil {
		delete(s.subs, sub.id)
	}
	s.subsMu.Unlock()
	if err != nil || sub == nil {
		return netconfSubError("ietf-subscribed-notifications:no-such-subscription",
			"no subscription %s on this session", idEl.Text)
	}
	sub.stop()
	return netconfOK
}

// start begins delivering updates. Runs after the establish reply is sent,
// by which time the session may have closed and stopped sub: the listener
// is registered under mu so a stop that already ran is seen and nothing is
// left registered on the engine.
func (sub *netconfSubscription) start() {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.stopped {
		return
	}
	if !sub.periodic {
		if ic := sub.sess.srv.ifCounters(); ic != nil && ic.State() != nil {
			sub.events = make(chan StateChange, netconfOnChangeBuffer)
			sub.state = ic.State()
			sub.state.AddListener(sub.events)
		}
	}
	go sub.run()
}

// stop ends delivery. Idempotent; the caller has already removed sub from
// its session.
func (sub *netconfSubscription) stop() {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.stopped {
		return
	}
	sub.stopped = true
	close(sub.quit)
	if sub.state != nil {
		sub.state.RemoveListener(sub.events)
	}
	sub.sess.srv.mgr.netconf.subscriptionsActive.Add(-1)
}

// complete ends the subscription at its stop-time. RFC 8639's
// subscription-completed is `if-feature configured`, so a publisher of
// dynamic subscriptions only cannot send it; what the reference
// implementation (sysrepo's srsn_stop_timer_cb, behind Netopeer2) sends
// instead is subscription-terminated with reason no-such-subscription,
// and nl6 matches it. A collector such as OpenNMS then re-subscribes.
func (sub *netconfSubscription) complete() {
	s := sub.sess
	s.subsMu.Lock()
	_, live := s.subs[sub.id]
	delete(s.subs, sub.id)
	s.subsMu.Unlock()
	if !live {
		return
	}
	sub.stop()
	_ = s.sendNotification(time.Now(), `<subscription-terminated xmlns="`+nsSubscribedNotif+`" xmlns:sn="`+nsSubscribedNotif+
		`"><id>`+strconv.FormatUint(uint64(sub.id), 10)+`</id><reason>sn:no-such-subscription</reason></subscription-terminated>`)
}

func (sub *netconfSubscription) run() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("netconf: subscription %d: recovered from panic: %v; closing its session", sub.id, r)
			sub.sess.close()
		}
	}()
	var stopC <-chan time.Time
	if !sub.stopTime.IsZero() {
		t := time.NewTimer(time.Until(sub.stopTime))
		defer t.Stop()
		stopC = t.C
	}
	if sub.periodic {
		sub.runPeriodic(stopC)
	} else {
		sub.runOnChange(stopC)
	}
}

// nextPeriodic returns the first update time at or after now: now itself
// without an anchor, else the next multiple of the period from the anchor.
func (sub *netconfSubscription) nextPeriodic(now time.Time) time.Time {
	if sub.anchor.IsZero() {
		return now
	}
	d := now.Sub(sub.anchor)
	k := d / sub.period
	if d%sub.period != 0 && d > 0 {
		k++
	}
	return sub.anchor.Add(k * sub.period)
}

func (sub *netconfSubscription) runPeriodic(stopC <-chan time.Time) {
	next := sub.nextPeriodic(time.Now())
	for {
		t := time.NewTimer(time.Until(next))
		select {
		case <-sub.quit:
			t.Stop()
			return
		case <-sub.sess.done:
			t.Stop()
			return
		case <-stopC:
			t.Stop()
			sub.complete()
			return
		case now := <-t.C:
			if sub.sendPushUpdate(now) != nil {
				return
			}
			next = next.Add(sub.period)
			if !next.After(now) { // the session stalled for longer than a period
				next = sub.nextPeriodic(now.Add(sub.period))
			}
		}
	}
}

// sendPushUpdate sends the filtered datastore contents at now.
func (sub *netconfSubscription) sendPushUpdate(now time.Time) error {
	nodes := applyNetconfFilter(sub.sess.srv.datastore(sub.datastore, now), sub.filter, sub.filtered)
	var b bytes.Buffer
	b.WriteString(`<push-update xmlns="` + nsYangPush + `"><id>`)
	b.WriteString(strconv.FormatUint(uint64(sub.id), 10))
	b.WriteString("</id>")
	if len(nodes) > 0 {
		b.WriteString("<datastore-contents>")
		writeNetconfNodes(&b, nodes, nsYangPush)
		b.WriteString("</datastore-contents>")
	}
	b.WriteString("</push-update>")
	if err := sub.sess.sendNotification(now, b.String()); err != nil {
		return err
	}
	sub.sess.srv.mgr.netconf.pushUpdates.Add(1)
	return nil
}

func (sub *netconfSubscription) runOnChange(stopC <-chan time.Time) {
	if sub.syncOnStart && sub.sendPushUpdate(time.Now()) != nil {
		return
	}
	if sub.events == nil {
		// No state engine: nothing on this device can change. Wait out the
		// subscription rather than end it, so the collector sees what a
		// quiet device looks like.
		select {
		case <-sub.quit:
		case <-sub.sess.done:
		case <-stopC:
			sub.complete()
		}
		return
	}
	// enabled is derived from admin-status, and an event carries the new
	// admin only, so the last value sent is kept per interface to tell
	// whether enabled moved.
	enabled := map[int]bool{}
	if v := sub.sess.srv.ifaces(); v != nil {
		if st := v.ic.State(); st != nil {
			for _, idx := range v.indices {
				enabled[idx] = st.AdminStatus(idx) != AdminDown
			}
		}
	}
	pending := map[int]StateChange{}
	var flush <-chan time.Time
	var flushTimer *time.Timer
	defer func() {
		if flushTimer != nil {
			flushTimer.Stop()
		}
	}()
	for {
		select {
		case <-sub.quit:
			return
		case <-sub.sess.done:
			return
		case <-stopC:
			sub.complete()
			return
		case evt := <-sub.events:
			if sub.dampening == 0 {
				if sub.sendChanges([]StateChange{evt}, enabled) != nil {
					return
				}
				continue
			}
			prev, ok := pending[evt.IfIndex]
			if ok {
				evt.Changed |= prev.Changed
			}
			pending[evt.IfIndex] = evt
			if flush == nil {
				flushTimer = time.NewTimer(sub.dampening)
				flush = flushTimer.C
			}
		case <-flush:
			flush, flushTimer = nil, nil
			batch := make([]StateChange, 0, len(pending))
			for _, evt := range pending {
				batch = append(batch, evt)
			}
			pending = map[int]StateChange{}
			if sub.sendChanges(batch, enabled) != nil {
				return
			}
		}
	}
}

// sendChanges sends one push-change-update for the events, one YANG Patch
// edit per changed leaf that the subscription's filter selects. Every edit
// is a replace: nl6 never creates or deletes an interface at runtime.
func (sub *netconfSubscription) sendChanges(events []StateChange, enabled map[int]bool) error {
	if sub.excluded["replace"] {
		return nil
	}
	v := sub.sess.srv.ifaces()
	if v == nil {
		return nil
	}
	ns := nsIETFInterfaces
	var edits bytes.Buffer
	n := 0
	for _, evt := range events {
		name, ok := v.names[evt.IfIndex]
		if !ok {
			continue // a shadowed duplicate name: not served, so not reported
		}
		entry := ncContainer(ns, "interface", ncLeaf(ns, "name", name))
		nowEnabled := evt.Admin != AdminDown
		if evt.Changed&LeafAdminStatus != 0 && enabled[evt.IfIndex] != nowEnabled {
			entry.Children = append(entry.Children, ncLeaf(ns, "enabled", strconv.FormatBool(nowEnabled)))
		}
		enabled[evt.IfIndex] = nowEnabled
		if sub.datastore == netconfOperational {
			if evt.Changed&LeafAdminStatus != 0 {
				entry.Children = append(entry.Children, ncLeaf(ns, "admin-status", netconfAdminStatus[evt.Admin]))
			}
			if evt.Changed&LeafOperStatus != 0 {
				entry.Children = append(entry.Children, ncLeaf(ns, "oper-status", netconfOperStatusName(evt.Oper)))
			}
			if evt.LastChangeNs != 0 && evt.LastChangeNs != LastChangeRewindSentinel {
				entry.Children = append(entry.Children, ncLeaf(ns, "last-change", netconfDateTime(time.Unix(0, int64(evt.LastChangeNs)))))
			}
		}
		if len(entry.Children) == 1 {
			continue
		}
		selected := applyNetconfFilter([]*ncNode{ncContainer(ns, "interfaces", entry)}, sub.filter, sub.filtered)
		if len(selected) == 0 || len(selected[0].Children) == 0 {
			continue
		}
		kept := selected[0].Children[0]
		for _, leaf := range kept.Children {
			if leaf.Name == "name" {
				continue // the key never changes
			}
			n++
			edits.WriteString("<edit><edit-id>edit-")
			edits.WriteString(strconv.Itoa(n))
			edits.WriteString("</edit-id><operation>replace</operation><target>/ietf-interfaces:interfaces/interface=")
			edits.WriteString(xmlEscapeString(restconfKeyEscape(name)))
			edits.WriteString("/")
			edits.WriteString(leaf.Name)
			edits.WriteString("</target><value>")
			writeNetconfNode(&edits, leaf, "")
			edits.WriteString("</value></edit>")
		}
	}
	if n == 0 {
		return nil
	}
	sub.patchSeq++
	var b bytes.Buffer
	b.WriteString(`<push-change-update xmlns="` + nsYangPush + `"><id>`)
	b.WriteString(strconv.FormatUint(uint64(sub.id), 10))
	b.WriteString("</id><datastore-changes><yang-patch><patch-id>patch-")
	b.WriteString(strconv.FormatUint(sub.patchSeq, 10))
	b.WriteString("</patch-id>")
	b.Write(edits.Bytes())
	b.WriteString("</yang-patch></datastore-changes></push-change-update>")
	if err := sub.sess.sendNotification(time.Now(), b.String()); err != nil {
		return err
	}
	sub.sess.srv.mgr.netconf.pushChangeUpdates.Add(1)
	return nil
}

// restconfKeyEscape percent-encodes a list key value for a RESTCONF data
// resource identifier (RFC 8040 §3.5.3): everything but RFC 3986 unreserved
// characters, so `GigabitEthernet0/1` becomes `GigabitEthernet0%2F1`.
func restconfKeyEscape(v string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}
