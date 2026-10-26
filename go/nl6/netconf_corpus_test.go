/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// shippedNetconfServer builds, for one shipped profile, the server half the
// datastore is rendered from, without a listener.
func shippedNetconfServer(t *testing.T, sm *SimulatorManager, profile string) *netconfServer {
	t.Helper()
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("load %s: %v", profile, err)
	}
	mc := NewMetricsCycler(0, GetDeviceProfile(""))
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	dev := &DeviceSimulator{ID: profile, IP: net.IPv4(10, 42, 0, 1), resources: res, metricsCycler: mc, resourceFile: profile}
	srv := &netconfServer{dev: dev}
	srv.events = newNetconfEventLog(srv)
	t.Cleanup(srv.events.close)
	return srv
}

// TestNetconfIfTypeCoversShippedCorpus fails by value when a shipped profile
// carries an ifType the iana-if-type map lacks, so no shipped interface is
// served as `other` by omission.
func TestNetconfIfTypeCoversShippedCorpus(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	missing := map[int][]string{}
	for _, profile := range shippedProfileNames(t) {
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatalf("load %s: %v", profile, err)
		}
		res.oidIndex.Range(func(k, v any) bool {
			oid, _ := k.(string)
			if !strings.HasPrefix(oid, ifTablePrefix+"3.") {
				return true
			}
			s, _ := v.(string)
			n, err := strconv.Atoi(s)
			if err != nil {
				return true
			}
			if _, ok := ianaIfTypeNames[n]; !ok {
				missing[n] = append(missing[n], profile)
			}
			return true
		})
	}
	for n, profiles := range missing {
		t.Errorf("ifType %d (in %v) has no iana-if-type identity in ianaIfTypeNames", n, profiles)
	}
}

// TestNetconfShippedProfilesRender renders both datastores of every shipped
// profile and checks the properties a validating client rejects a whole
// reply for: unique list keys and layer references that resolve.
func TestNetconfShippedProfilesRender(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	served := 0
	for _, profile := range shippedProfileNames(t) {
		srv := shippedNetconfServer(t, sm, profile)
		for _, ds := range []netconfDatastoreName{netconfOperational, netconfRunning} {
			nodes := srv.datastore(ds, time.Now())
			var ifs *ncNode
			for _, n := range nodes {
				if n.Name == "interfaces" {
					ifs = n
				}
			}
			if ifs == nil {
				continue
			}
			names := map[string]bool{}
			for _, e := range ifs.Children {
				name := e.Children[0].Value
				if names[name] {
					t.Errorf("%s %s: duplicate interface name %q", profile, ds, name)
				}
				names[name] = true
			}
			for _, e := range ifs.Children {
				for _, c := range e.Children {
					if (c.Name == "higher-layer-if" || c.Name == "lower-layer-if") && !names[c.Value] {
						t.Errorf("%s: %s %s=%q names no served interface", profile, e.Children[0].Value, c.Name, c.Value)
					}
				}
			}
			if ds == netconfOperational {
				served += len(ifs.Children)
			}
		}
	}
	if served == 0 {
		t.Fatal("no interfaces rendered. Is the test running from go/nl6?")
	}
	t.Logf("rendered %d operational interface entries across the shipped profiles", served)
}

// TestNetconfShadowedNamesAreCounted pins the duplicate-name rule: the lower
// ifIndex keeps the name, the higher one is not served.
func TestNetconfShadowedNamesAreCounted(t *testing.T) {
	dev := newTestGnmiDevice(t, 3)
	dev.resources.oidIndex.Store(".1.3.6.1.2.1.2.2.1.2.3", "TestIf1")
	v := buildNetconfIfaces(dev, dev.metricsCycler.ifCounters.Load())
	got := append([]int(nil), v.indices...)
	sort.Ints(got)
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("served ifIndex %v, want [1 2]", got)
	}
}

// TestNetconfOperationalServesEveryStateTree pins the top-level trees the
// operational datastore must carry. The interop check validates with
// yanglint -e, which requires only the modules whose data is present, so an
// omitted tree would pass there; this is what fails instead.
func TestNetconfOperationalServesEveryStateTree(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	srv := shippedNetconfServer(t, sm, shippedProfileNames(t)[0])
	got := map[string]bool{}
	for _, n := range srv.datastore(netconfOperational, time.Now()) {
		got[n.NS+" "+n.Name] = true
	}
	for _, want := range []string{
		nsIETFInterfaces + " interfaces",
		nsYangLibrary + " yang-library",
		nsYangLibrary + " modules-state",
		nsNetconfMonitoring + " netconf-state",
		nsAlarms + " alarms",
		nsSubscribedNotif + " streams",
		nsNetmodNotification + " netconf",
	} {
		if !got[want] {
			t.Errorf("operational datastore lacks %s", want)
		}
	}
}
