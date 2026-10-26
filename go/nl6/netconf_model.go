/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"log"
	"sort"
	"strconv"
	"sync"
	"time"
)

// The NETCONF server's data model: ietf-interfaces (RFC 8343, NMDA form)
// built from the interface state engine and counter cycler that SNMP and
// gNMI read, plus the RFC 8525 YANG library describing what is served.
//
// ietf-interfaces rather than the OpenConfig catalogue gNMI serves, for two
// reasons. It is the model NETCONF collectors and IETF-model devices use for
// YANG-Push, and it maps one to one onto IF-MIB. And the catalogue's JSON
// fold carries no per-element module, which XML needs at every augment
// boundary, so serving it here would first need the generator to emit
// namespaces.

// netconfModule is one row of the YANG library.
type netconfModule struct {
	Name, Revision, Namespace string
	Features                  []string
	ImportOnly                bool
	// YANG10 marks a `yang-version 1` module. RFC 7950 §5.6.4 has those
	// listed in the hello as well as in the library, and libnetconf2 will
	// not build a session without ietf-netconf among them.
	YANG10 bool
}

// netconfModules is the served schema. The import-only rows are the import
// closure of the implemented ones, computed from the published modules
// rather than recalled; a client that fetches modules by this list gets a
// set that resolves.
var netconfModules = []netconfModule{
	{Name: "ietf-interfaces", Revision: "2018-02-20", Namespace: nsIETFInterfaces, Features: []string{"if-mib"}},
	{Name: "iana-if-type", Revision: "2014-05-08", Namespace: nsIANAIfType, YANG10: true},
	{Name: "ietf-yang-library", Revision: "2019-01-04", Namespace: nsYangLibrary},
	{Name: "ietf-datastores", Revision: "2018-02-14", Namespace: nsDatastores},
	{Name: "ietf-netconf", Revision: "2011-06-01", Namespace: nsNetconfBase, YANG10: true},
	{Name: "ietf-netconf-nmda", Revision: "2019-01-07", Namespace: nsNetconfNMDA},
	{Name: "ietf-subscribed-notifications", Revision: "2019-09-09", Namespace: nsSubscribedNotif, Features: []string{"encode-xml", "replay", "subtree", "xpath"}},
	{Name: "ietf-yang-push", Revision: "2019-09-09", Namespace: nsYangPush, Features: []string{"on-change"}},
	{Name: "ietf-alarms", Revision: "2019-09-11", Namespace: nsAlarms},
	{Name: "nl6-alarm-types", Revision: "2026-10-26", Namespace: nsNl6AlarmTypes},
	{Name: "ietf-netconf-notifications", Revision: "2012-02-06", Namespace: nsNetconfNotifications, YANG10: true},
	{Name: "ietf-netconf-monitoring", Revision: "2010-10-04", Namespace: nsNetconfMonitoring, YANG10: true},
	// RFC 5277's create-subscription, replayComplete, notificationComplete and
	// /netconf/streams, in CESNET's YANG rendering of the RFC's XSD. Listing
	// them is also what keeps libnetconf2 clients alive: one that sees
	// :notification:1.0 without them appends the two to its module array
	// without terminating it, and crashes (libnetconf2 v3.7.1,
	// build_module_info_yl).
	{Name: "notifications", Revision: "2008-07-14", Namespace: nsNetconfNotif, YANG10: true},
	{Name: "nc-notifications", Revision: "2008-07-14", Namespace: nsNetmodNotification, YANG10: true},
	{Name: "ietf-yang-types", Revision: "2013-07-15", Namespace: "urn:ietf:params:xml:ns:yang:ietf-yang-types", ImportOnly: true},
	{Name: "ietf-inet-types", Revision: "2013-07-15", Namespace: "urn:ietf:params:xml:ns:yang:ietf-inet-types", ImportOnly: true},
	{Name: "ietf-netconf-acm", Revision: "2018-02-14", Namespace: "urn:ietf:params:xml:ns:yang:ietf-netconf-acm", ImportOnly: true},
	{Name: "ietf-network-instance", Revision: "2019-01-21", Namespace: "urn:ietf:params:xml:ns:yang:ietf-network-instance", ImportOnly: true},
	{Name: "ietf-ip", Revision: "2018-02-22", Namespace: "urn:ietf:params:xml:ns:yang:ietf-ip", ImportOnly: true},
	{Name: "ietf-yang-schema-mount", Revision: "2019-01-14", Namespace: "urn:ietf:params:xml:ns:yang:ietf-yang-schema-mount", ImportOnly: true},
	{Name: "ietf-restconf", Revision: "2017-01-26", Namespace: "urn:ietf:params:xml:ns:yang:ietf-restconf", ImportOnly: true},
	{Name: "ietf-yang-patch", Revision: "2017-02-22", Namespace: "urn:ietf:params:xml:ns:yang:ietf-yang-patch", ImportOnly: true},
	{Name: "ietf-origin", Revision: "2018-02-14", Namespace: "urn:ietf:params:xml:ns:yang:ietf-origin", ImportOnly: true},
	{Name: "ietf-yang-metadata", Revision: "2016-08-05", Namespace: "urn:ietf:params:xml:ns:yang:ietf-yang-metadata", ImportOnly: true},
	{Name: "ietf-netconf-with-defaults", Revision: "2011-06-01", Namespace: "urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults", ImportOnly: true},
}

// netconfLibraryContentID identifies the schema above. It changes only
// when netconfModules does, so bump it with any edit to that table.
const netconfLibraryContentID = "nl6-netconf-3"

// netconfModuleNamespace returns the namespace of a served module, or "".
func netconfModuleNamespace(name string) string {
	for _, m := range netconfModules {
		if m.Name == name {
			return m.Namespace
		}
	}
	return ""
}

// netconfYangLibrary renders /yang-library (RFC 8525). Both datastores nl6
// answers for share the one schema.
func netconfYangLibrary() *ncNode {
	set := ncContainer(nsYangLibrary, "module-set", ncLeaf(nsYangLibrary, "name", "nl6"))
	for _, m := range netconfModules {
		kind := "module"
		if m.ImportOnly {
			kind = "import-only-module"
		}
		row := ncContainer(nsYangLibrary, kind,
			ncLeaf(nsYangLibrary, "name", m.Name),
			ncLeaf(nsYangLibrary, "revision", m.Revision),
			ncLeaf(nsYangLibrary, "namespace", m.Namespace))
		for _, f := range m.Features {
			row.Children = append(row.Children, ncLeaf(nsYangLibrary, "feature", f))
		}
		set.Children = append(set.Children, row)
	}
	lib := ncContainer(nsYangLibrary, "yang-library", set,
		ncContainer(nsYangLibrary, "schema",
			ncLeaf(nsYangLibrary, "name", "nl6"),
			ncLeaf(nsYangLibrary, "module-set", "nl6")))
	for _, ds := range []string{"running", "operational"} {
		name := &ncNode{NS: nsYangLibrary, Name: "name", Value: "ds:" + ds, Leaf: true, ValuePrefix: "ds", ValueNS: nsDatastores}
		lib.Children = append(lib.Children, ncContainer(nsYangLibrary, "datastore", name, ncLeaf(nsYangLibrary, "schema", "nl6")))
	}
	lib.Children = append(lib.Children, ncLeaf(nsYangLibrary, "content-id", netconfLibraryContentID))
	return lib
}

// netconfModulesState renders the RFC 7895 /modules-state. It is
// deprecated by RFC 8525 but still in ietf-yang-library@2019-01-04, where
// module-set-id is mandatory under a non-presence container, so a complete
// operational datastore without it does not validate. Older clients, and
// OpenNMS when /yang-library reads empty, read this instead.
func netconfModulesState() *ncNode {
	ms := ncContainer(nsYangLibrary, "modules-state", ncLeaf(nsYangLibrary, "module-set-id", netconfLibraryContentID))
	for _, m := range netconfModules {
		conformance := "implement"
		if m.ImportOnly {
			conformance = "import"
		}
		row := ncContainer(nsYangLibrary, "module",
			ncLeaf(nsYangLibrary, "name", m.Name),
			ncLeaf(nsYangLibrary, "revision", m.Revision),
			ncLeaf(nsYangLibrary, "namespace", m.Namespace))
		for _, f := range m.Features {
			row.Children = append(row.Children, ncLeaf(nsYangLibrary, "feature", f))
		}
		row.Children = append(row.Children, ncLeaf(nsYangLibrary, "conformance-type", conformance))
		ms.Children = append(ms.Children, row)
	}
	return ms
}

// ianaIfTypeNames maps IANAifType-MIB values to iana-if-type identities.
// The identity names are those of the MIB enum labels; every name here was
// checked against iana-if-type@2014-05-08. TestNetconfIfTypeCoversShippedCorpus
// fails by value when a shipped profile uses a type missing here.
var ianaIfTypeNames = map[int]string{
	1:   "other",
	6:   "ethernetCsmacd",
	22:  "propPointToPointSerial",
	23:  "ppp",
	24:  "softwareLoopback",
	32:  "frameRelay",
	37:  "atm",
	39:  "sonet",
	53:  "propVirtual",
	62:  "fastEther",
	71:  "ieee80211",
	117: "gigabitEthernet",
	131: "tunnel",
	135: "l2vlan",
	136: "l3ipvlan",
	150: "mplsTunnel",
	161: "ieee8023adLag",
	166: "mpls",
	195: "opticalChannel",
	199: "infiniband",
	209: "bridge",
}

var netconfUnmappedIfTypeOnce sync.Map // ifType -> struct{}

// ianaIfTypeIdentity returns the identity for an ifType, falling back to
// `other` (which is what IANAifType-MIB's own value 1 means) for a value
// the table does not carry, logged once per value.
func ianaIfTypeIdentity(ifType int) string {
	if name, ok := ianaIfTypeNames[ifType]; ok {
		return name
	}
	if ifType == 0 { // the profile carries no ifType row for the interface
		return "other"
	}
	if _, seen := netconfUnmappedIfTypeOnce.LoadOrStore(ifType, struct{}{}); !seen {
		log.Printf("netconf: ifType %d has no iana-if-type mapping in nl6; serving it as ianaift:other", ifType)
	}
	return "other"
}

// RFC 8343 enumerations, indexed by the IF-MIB integer.
var (
	netconfAdminStatus = map[uint8]string{AdminUp: "up", AdminDown: "down", AdminTesting: "testing"}
	netconfOperStatus  = map[uint8]string{
		OperUp: "up", OperDown: "down", OperTesting: "testing", OperUnknown: "unknown",
		OperDormant: "dormant", OperNotPresent: "not-present", OperLowerLayerDn: "lower-layer-down",
	}
)

// netconfStatistics maps RFC 8343 statistics leaves, in YANG order, to the
// cycler column that serves them. The HC column wherever IF-MIB has one, as
// gNMI does, so every protocol reads the same counter.
var netconfStatistics = []struct {
	leaf   string
	prefix string
	column int
}{
	{"in-octets", ifXTablePrefix, colIfHCInOctets},
	{"in-unicast-pkts", ifXTablePrefix, colIfHCInUcastPkts},
	{"in-broadcast-pkts", ifXTablePrefix, colIfHCInBroadcastPkts},
	{"in-multicast-pkts", ifXTablePrefix, colIfHCInMulticastPkts},
	{"in-discards", ifTablePrefix, colIfInDiscards},
	{"in-errors", ifTablePrefix, colIfInErrors},
	{"out-octets", ifXTablePrefix, colIfHCOutOctets},
	{"out-unicast-pkts", ifXTablePrefix, colIfHCOutUcastPkts},
	{"out-broadcast-pkts", ifXTablePrefix, colIfHCOutBroadcastPkts},
	{"out-multicast-pkts", ifXTablePrefix, colIfHCOutMulticastPkts},
	{"out-discards", ifTablePrefix, colIfOutDiscards},
	{"out-errors", ifTablePrefix, colIfOutErrors},
}

// netconfIfaces is a device's interface list as NETCONF serves it: names
// fixed at first use, ordered by ifIndex, unique. The list key must be
// unique, so a second ifIndex carrying an ifDescr already taken is left
// out (logged once per device) rather than served as a duplicate entry a
// validating client would reject the whole reply for.
type netconfIfaces struct {
	ic      *IfCounterCycler
	indices []int
	names   map[int]string
	types   map[int]int // IANAifType; 0 (absent from the profile) serves as other
	byName  map[string]int
	lower   map[int][]string // ifIndex -> lower-layer-if names
	higher  map[int][]string // ifIndex -> higher-layer-if names
}

func buildNetconfIfaces(d *DeviceSimulator, ic *IfCounterCycler) *netconfIfaces {
	v := &netconfIfaces{ic: ic, names: map[int]string{}, types: map[int]int{}, byName: map[string]int{},
		lower: map[int][]string{}, higher: map[int][]string{}}
	all := append([]int(nil), ic.IfIndices()...)
	sort.Ints(all)
	var dropped []string
	for _, idx := range all {
		name := lookupIfDescr(d, idx)
		if name == "" {
			name = synthIfName(idx)
		}
		if prev, taken := v.byName[name]; taken {
			dropped = append(dropped, strconv.Itoa(idx)+" (duplicates "+strconv.Itoa(prev)+")")
			continue
		}
		v.names[idx] = name
		v.types[idx] = lookupIfType(d, idx)
		v.byName[name] = idx
		v.indices = append(v.indices, idx)
	}
	if len(dropped) > 0 && d != nil && d.IP != nil {
		log.Printf("netconf: device %s (%s): ifIndex %v not served, their ifDescr repeats an earlier interface's (list keys must be unique)",
			d.IP, d.resourceFile, dropped)
	}
	if st := ic.State(); st != nil {
		for _, idx := range v.indices {
			if p := st.Parent(idx); p != 0 {
				if pn, ok := v.names[p]; ok {
					v.lower[idx] = append(v.lower[idx], pn)
					v.higher[p] = append(v.higher[p], v.names[idx])
				}
			}
		}
	}
	return v
}

// netconfDateTime renders a yang:date-and-time in UTC.
func netconfDateTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// entry renders one interface list entry. config limits it to the running
// datastore's config nodes; otherwise it is the operational entry, counters
// read at tSec on the cycler's clock.
func (v *netconfIfaces) entry(idx int, config bool, tSec float64) *ncNode {
	ns := nsIETFInterfaces
	e := ncContainer(ns, "interface", ncLeaf(ns, "name", v.names[idx]))
	e.Children = append(e.Children, &ncNode{NS: ns, Name: "type", Leaf: true,
		Value: "ianaift:" + ianaIfTypeIdentity(v.types[idx]), ValuePrefix: "ianaift", ValueNS: nsIANAIfType})
	st := v.ic.State()
	snap := StateSnapshot{Oper: OperUp, Admin: AdminUp, LastChangeNs: LastChangeRewindSentinel}
	if st != nil {
		snap = st.Snapshot(idx)
	}
	e.Children = append(e.Children, ncLeaf(ns, "enabled", strconv.FormatBool(snap.Admin != AdminDown)))
	if config {
		return e
	}
	e.Children = append(e.Children,
		ncLeaf(ns, "admin-status", netconfAdminStatus[snap.Admin]),
		ncLeaf(ns, "oper-status", netconfOperStatusName(snap.Oper)))
	if snap.LastChangeNs != LastChangeRewindSentinel && snap.LastChangeNs != 0 {
		e.Children = append(e.Children, ncLeaf(ns, "last-change", netconfDateTime(time.Unix(0, int64(snap.LastChangeNs)))))
	}
	e.Children = append(e.Children, ncLeaf(ns, "if-index", strconv.Itoa(idx)))
	for _, h := range v.higher[idx] {
		e.Children = append(e.Children, ncLeaf(ns, "higher-layer-if", h))
	}
	for _, l := range v.lower[idx] {
		e.Children = append(e.Children, ncLeaf(ns, "lower-layer-if", l))
	}
	if slot := idx - 1; slot >= 0 && slot < len(v.ic.ifSpeedBps) && v.ic.ifSpeedBps[slot] > 0 {
		e.Children = append(e.Children, ncLeaf(ns, "speed", strconv.FormatUint(v.ic.ifSpeedBps[slot], 10)))
	}
	stats := ncContainer(ns, "statistics", ncLeaf(ns, "discontinuity-time", netconfDateTime(v.ic.startTime)))
	for _, c := range netconfStatistics {
		raw := v.ic.GetDynamicAt(c.prefix+strconv.Itoa(c.column)+"."+strconv.Itoa(idx), tSec)
		if _, err := strconv.ParseUint(raw, 10, 64); err != nil {
			continue
		}
		stats.Children = append(stats.Children, ncLeaf(ns, c.leaf, raw))
	}
	e.Children = append(e.Children, stats)
	return e
}

// netconfInterfaceConfigNodes are the config nodes of an interface entry;
// every other node nl6 serves is config false.
var netconfInterfaceConfigNodes = map[string]bool{"name": true, "type": true, "enabled": true}

// netconfConfigFilter applies get-data's config-filter (RFC 8526 §3.1.1):
// "true" keeps config nodes, "false" keeps config false nodes plus the list
// keys that locate them, "" keeps everything. libnetconf2 sends "false"
// when it reads the YANG library, which is how this was found.
func netconfConfigFilter(nodes []*ncNode, mode string) []*ncNode {
	if mode == "" {
		return nodes
	}
	var out []*ncNode
	for _, n := range nodes {
		if n.NS != nsIETFInterfaces || n.Name != "interfaces" {
			if mode == "false" { // yang-library and modules-state are config false
				out = append(out, n)
			}
			continue
		}
		ifs := ncContainer(n.NS, n.Name)
		for _, e := range n.Children {
			entry := ncContainer(e.NS, e.Name)
			for _, c := range e.Children {
				if c.Name == "name" || netconfInterfaceConfigNodes[c.Name] == (mode == "true") {
					entry.Children = append(entry.Children, c)
				}
			}
			ifs.Children = append(ifs.Children, entry)
		}
		out = append(out, ifs)
	}
	return out
}

func netconfOperStatusName(v uint8) string {
	if s, ok := netconfOperStatus[v]; ok {
		return s
	}
	return "unknown"
}
