/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"embed"
	"strings"
)

// RFC 6022 get-schema. Every module of the YANG library is embedded, so a
// client can build its schema from the device alone. libnetconf2 looks for
// a module locally first and asks get-schema second, so nl6's own
// nl6-alarm-types, which no client has, depends on this, and so does the
// RFC 6241 ietf-netconf revision, which libnetconf2 ships only in its own
// variant. Provenance: netconf_yang/SOURCES.tsv.

//go:embed netconf_yang/*.yang
var netconfYangFS embed.FS

// netconfModuleSource returns the YANG text of a served module.
func netconfModuleSource(m netconfModule) (string, bool) {
	b, err := netconfYangFS.ReadFile("netconf_yang/" + m.Name + "@" + m.Revision + ".yang")
	if err != nil {
		return "", false
	}
	return string(b), true
}

// netconfMonitoringSchemas renders /netconf-state/schemas, the list a
// client reads to learn what get-schema answers.
func netconfMonitoringSchemas() *ncNode {
	ns := nsNetconfMonitoring
	schemas := ncContainer(ns, "schemas")
	for _, m := range netconfModules {
		schemas.Children = append(schemas.Children, ncContainer(ns, "schema",
			ncLeaf(ns, "identifier", m.Name),
			ncLeaf(ns, "version", m.Revision),
			&ncNode{NS: ns, Name: "format", Value: "ncm:yang", Leaf: true, ValuePrefix: "ncm", ValueNS: ns},
			ncLeaf(ns, "namespace", m.Namespace),
			ncLeaf(ns, "location", "NETCONF")))
	}
	return ncContainer(ns, "netconf-state", schemas)
}

// opGetSchema answers get-schema with the module text as the data element's
// character content.
func (s *netconfSession) opGetSchema(op *xmlElem) netconfRPCResult {
	var id, version string
	for _, c := range op.Children {
		if c.Space != nsNetconfMonitoring {
			return netconfRPCResult{err: netconfUnknownElement(c)}
		}
		switch c.Local {
		case "identifier":
			id = c.Text
		case "version":
			version = c.Text
		case "format":
			if c.Text != "yang" && !strings.HasSuffix(c.Text, ":yang") {
				return netconfRPCResult{err: netconfErr("application", "invalid-value", "nl6 serves schemas in YANG format only, not %s", c.Text)}
			}
		default:
			return netconfRPCResult{err: netconfUnknownElement(c)}
		}
	}
	if id == "" {
		e := netconfErr("protocol", "missing-element", "get-schema needs an identifier")
		e.Info = netconfBadElement("identifier")
		return netconfRPCResult{err: e}
	}
	for _, m := range netconfModules {
		if m.Name != id || (version != "" && version != m.Revision) {
			continue
		}
		text, ok := netconfModuleSource(m)
		if !ok {
			break
		}
		return netconfRPCResult{body: `<data xmlns="` + nsNetconfMonitoring + `">` + xmlEscapeString(text) + `</data>`}
	}
	return netconfRPCResult{err: netconfErr("application", "invalid-value", "no schema %s%s", id, map[bool]string{true: "@" + version}[version != ""])}
}
