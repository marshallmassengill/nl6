/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A device's NETCONF event stream: the one stream RFC 5277 and RFC 8639
// call NETCONF, carrying RFC 8632 alarm-notifications for interface links
// and RFC 6470 session-start / session-end. The log is written whether or
// not anyone is subscribed, which is what makes the alarm list and replay
// truthful for a collector that connects later. It is fed by a synchronous
// observer on the interface state engine, so a device costs no goroutine.

// netconfStreamName is the stream RFC 5277 §3.2.3 makes the default.
const netconfStreamName = "NETCONF"

// netconfReplayCapacity bounds the replay buffer per device. Records are
// compact (no XML), and rendered when sent.
const netconfReplayCapacity = 256

// netconfStreamBuffer is a stream subscription's queue depth; the oldest
// record is dropped when it is full.
const netconfStreamBuffer = 64

type netconfEventKind uint8

const (
	netconfEventAlarm netconfEventKind = iota + 1
	netconfEventSessionStart
	netconfEventSessionEnd
)

// netconfEvent is one record of the stream.
type netconfEvent struct {
	seq  uint64
	at   time.Time
	kind netconfEventKind

	ifIndex int  // alarm
	cleared bool // alarm

	sessionID, killedBy uint32 // session
	user, source        string // session
	reason              string // session-end termination-reason
}

// netconfAlarm is one entry of the alarm list. A cleared alarm stays in the
// list with is-cleared true, as RFC 8632 §3.5 intends: purging is an
// operator action, and nl6 has none.
type netconfAlarm struct {
	created, lastRaised, lastChanged time.Time
	cleared                          bool
}

type netconfEventLog struct {
	srv *netconfServer

	mu      sync.Mutex
	created time.Time
	aged    time.Time // time of the newest record dropped from the buffer
	ring    []netconfEvent
	head    int // index of the oldest record once the ring is full
	seq     uint64

	alarms        map[int]*netconfAlarm
	alarmsChanged time.Time

	subs           map[*netconfSubscription]struct{}
	removeObserver func()
}

// netconfLinkAlarmActive is the link-down rule: admin up and oper down.
// Admin down is a deliberate shutdown, not a fault, and lower-layer-down
// is a consequence of the parent's alarm rather than an alarm of its own.
func netconfLinkAlarmActive(s StateSnapshot) bool {
	return s.Admin == AdminUp && s.Oper == OperDown
}

// newNetconfEventLog starts the log, seeding the alarm list from the state
// in force: an interface already down when the device started has a raised
// alarm dated from its last change, and no notification, since nothing
// changed while anyone could have been listening.
func newNetconfEventLog(srv *netconfServer) *netconfEventLog {
	now := time.Now()
	l := &netconfEventLog{srv: srv, created: now, alarms: map[int]*netconfAlarm{},
		subs: map[*netconfSubscription]struct{}{}}
	v := srv.ifaces()
	if v == nil || v.ic.State() == nil {
		return l
	}
	st := v.ic.State()
	for _, idx := range v.indices {
		snap := st.Snapshot(idx)
		if !netconfLinkAlarmActive(snap) {
			continue
		}
		t := now
		if snap.LastChangeNs != 0 && snap.LastChangeNs != LastChangeRewindSentinel {
			t = time.Unix(0, int64(snap.LastChangeNs))
		}
		l.alarms[idx] = &netconfAlarm{created: t, lastRaised: t, lastChanged: t}
		if t.After(l.alarmsChanged) {
			l.alarmsChanged = t
		}
	}
	l.removeObserver = st.AddObserver(l.onState)
	return l
}

func (l *netconfEventLog) close() {
	if l.removeObserver != nil {
		l.removeObserver()
	}
}

// onState runs on the mutating goroutine. It re-reads the interface rather
// than trusting the event's values, so two concurrent mutators that
// broadcast out of order still leave the alarm matching the state.
func (l *netconfEventLog) onState(evt StateChange) {
	v := l.srv.ifaces()
	if v == nil {
		return
	}
	if _, served := v.names[evt.IfIndex]; !served {
		return
	}
	st := v.ic.State()
	l.mu.Lock()
	defer l.mu.Unlock()
	active := netconfLinkAlarmActive(st.Snapshot(evt.IfIndex))
	a := l.alarms[evt.IfIndex]
	at := evt.At
	if at.IsZero() {
		at = time.Now()
	}
	switch {
	case active && (a == nil || a.cleared):
		if a == nil {
			a = &netconfAlarm{created: at}
			l.alarms[evt.IfIndex] = a
		}
		a.cleared, a.lastRaised, a.lastChanged = false, at, at
	case !active && a != nil && !a.cleared:
		a.cleared, a.lastChanged = true, at
	default:
		return
	}
	l.alarmsChanged = at
	l.appendLocked(netconfEvent{at: at, kind: netconfEventAlarm, ifIndex: evt.IfIndex, cleared: !active})
}

// sessionEvent records a session starting or ending.
func (l *netconfEventLog) sessionEvent(ev netconfEvent) {
	ev.at = time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.appendLocked(ev)
}

func (l *netconfEventLog) appendLocked(ev netconfEvent) {
	l.seq++
	ev.seq = l.seq
	if len(l.ring) < netconfReplayCapacity {
		l.ring = append(l.ring, ev)
	} else {
		l.aged = l.ring[l.head].at
		l.ring[l.head] = ev
		l.head = (l.head + 1) % netconfReplayCapacity
	}
	for sub := range l.subs {
		sub.deliver(ev)
	}
}

// subscribe registers sub for live records and, when from is non-zero,
// returns the buffered records at or after it, oldest first. Both happen
// under one lock, so no record is missed between replay and live, and none
// is sent twice.
func (l *netconfEventLog) subscribe(sub *netconfSubscription, from time.Time) []netconfEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.subs[sub] = struct{}{}
	if from.IsZero() {
		return nil
	}
	var out []netconfEvent
	for i := 0; i < len(l.ring); i++ {
		ev := l.ring[(l.head+i)%len(l.ring)]
		if !ev.at.Before(from) {
			out = append(out, ev)
		}
	}
	return out
}

func (l *netconfEventLog) unsubscribe(sub *netconfSubscription) {
	l.mu.Lock()
	delete(l.subs, sub)
	l.mu.Unlock()
}

// replayFloor is the earliest time replay can reach: the newest dropped
// record, once any was dropped, else the log's creation.
func (l *netconfEventLog) replayFloor() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.aged.IsZero() {
		return l.aged
	}
	return l.created
}

// interfaceInstance renders the instance-identifier of an interface for an
// alarm resource, with the if prefix the caller declares.
func netconfInterfaceInstance(name string) string {
	q := "'"
	if strings.Contains(name, "'") {
		q = `"`
	}
	return "/if:interfaces/if:interface[if:name=" + q + name + q + "]"
}

func netconfAlarmResource(ns, name string) *ncNode {
	return &ncNode{NS: ns, Name: "resource", Leaf: true, Value: netconfInterfaceInstance(name),
		ValuePrefix: "if", ValueNS: nsIETFInterfaces}
}

func netconfLinkDownType(ns string) *ncNode {
	return &ncNode{NS: ns, Name: "alarm-type-id", Leaf: true, Value: "nl6-at:link-down",
		ValuePrefix: "nl6-at", ValueNS: nsNl6AlarmTypes}
}

func netconfAlarmText(name string, cleared bool) string {
	if cleared {
		return "Interface " + name + " is up"
	}
	return "Interface " + name + " is down"
}

// render returns the notification content for ev, or nil when it names an
// interface the device does not serve.
func (l *netconfEventLog) render(ev netconfEvent) *ncNode {
	switch ev.kind {
	case netconfEventAlarm:
		v := l.srv.ifaces()
		if v == nil {
			return nil
		}
		name, ok := v.names[ev.ifIndex]
		if !ok {
			return nil
		}
		severity := "major"
		if ev.cleared {
			severity = "cleared"
		}
		ns := nsAlarms
		return ncContainer(ns, "alarm-notification",
			netconfAlarmResource(ns, name),
			netconfLinkDownType(ns),
			ncLeaf(ns, "alarm-type-qualifier", ""),
			ncLeaf(ns, "time", netconfDateTime(ev.at)),
			ncLeaf(ns, "perceived-severity", severity),
			ncLeaf(ns, "alarm-text", netconfAlarmText(name, ev.cleared)))
	case netconfEventSessionStart, netconfEventSessionEnd:
		ns := nsNetconfNotifications
		name := "netconf-session-start"
		if ev.kind == netconfEventSessionEnd {
			name = "netconf-session-end"
		}
		n := ncContainer(ns, name,
			ncLeaf(ns, "username", ev.user),
			ncLeaf(ns, "session-id", strconv.FormatUint(uint64(ev.sessionID), 10)))
		if ev.source != "" {
			n.Children = append(n.Children, ncLeaf(ns, "source-host", ev.source))
		}
		if ev.kind == netconfEventSessionEnd {
			if ev.killedBy != 0 {
				n.Children = append(n.Children, ncLeaf(ns, "killed-by", strconv.FormatUint(uint64(ev.killedBy), 10)))
			}
			n.Children = append(n.Children, ncLeaf(ns, "termination-reason", ev.reason))
		}
		return n
	}
	return nil
}

// alarmsNode renders /alarms: the inventory of what can be raised and the
// alarm list.
func (l *netconfEventLog) alarmsNode() *ncNode {
	ns := nsAlarms
	inventory := ncContainer(ns, "alarm-inventory", ncContainer(ns, "alarm-type",
		netconfLinkDownType(ns),
		ncLeaf(ns, "alarm-type-qualifier", ""),
		ncLeaf(ns, "will-clear", "true"),
		ncLeaf(ns, "severity-level", "major"),
		ncLeaf(ns, "description", "An administratively up interface whose operational status is down. "+
			"Cleared when it comes up or is shut down.")))
	list := ncContainer(ns, "alarm-list")
	v := l.srv.ifaces()
	l.mu.Lock()
	idx := make([]int, 0, len(l.alarms))
	for i := range l.alarms {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var entries []*ncNode
	for _, i := range idx {
		name, ok := "", false
		if v != nil {
			name, ok = v.names[i]
		}
		if !ok {
			continue
		}
		a := l.alarms[i]
		entries = append(entries, ncContainer(ns, "alarm",
			netconfAlarmResource(ns, name),
			netconfLinkDownType(ns),
			ncLeaf(ns, "alarm-type-qualifier", ""),
			ncLeaf(ns, "time-created", netconfDateTime(a.created)),
			ncLeaf(ns, "is-cleared", strconv.FormatBool(a.cleared)),
			ncLeaf(ns, "last-raised", netconfDateTime(a.lastRaised)),
			ncLeaf(ns, "last-changed", netconfDateTime(a.lastChanged)),
			ncLeaf(ns, "perceived-severity", "major"),
			ncLeaf(ns, "alarm-text", netconfAlarmText(name, a.cleared))))
	}
	changed := l.alarmsChanged
	l.mu.Unlock()
	list.Children = append(list.Children, ncLeaf(ns, "number-of-alarms", strconv.Itoa(len(entries))))
	if !changed.IsZero() {
		list.Children = append(list.Children, ncLeaf(ns, "last-changed", netconfDateTime(changed)))
	}
	list.Children = append(list.Children, entries...)
	return ncContainer(ns, "alarms", inventory, list)
}

// netconfStreamsNode renders RFC 5277's /netconf/streams.
func (l *netconfEventLog) netconfStreamsNode() *ncNode {
	ns := nsNetmodNotification
	l.mu.Lock()
	created, aged := l.created, l.aged
	l.mu.Unlock()
	stream := ncContainer(ns, "stream",
		ncLeaf(ns, "name", netconfStreamName),
		ncLeaf(ns, "description", "Link alarms (RFC 8632) and NETCONF session events (RFC 6470)"),
		ncLeaf(ns, "replaySupport", "true"),
		ncLeaf(ns, "replayLogCreationTime", netconfDateTime(created)))
	if !aged.IsZero() {
		stream.Children = append(stream.Children, ncLeaf(ns, "replayLogAgedTime", netconfDateTime(aged)))
	}
	return ncContainer(ns, "netconf", ncContainer(ns, "streams", stream))
}

// streamsNode renders RFC 8639's /streams.
func (l *netconfEventLog) streamsNode() *ncNode {
	ns := nsSubscribedNotif
	l.mu.Lock()
	created, aged := l.created, l.aged
	l.mu.Unlock()
	stream := ncContainer(ns, "stream",
		ncLeaf(ns, "name", netconfStreamName),
		ncLeaf(ns, "description", "Link alarms (RFC 8632) and NETCONF session events (RFC 6470)"),
		ncLeaf(ns, "replay-support", ""),
		ncLeaf(ns, "replay-log-creation-time", netconfDateTime(created)))
	if !aged.IsZero() {
		stream.Children = append(stream.Children, ncLeaf(ns, "replay-log-aged-time", netconfDateTime(aged)))
	}
	return ncContainer(ns, "streams", stream)
}
