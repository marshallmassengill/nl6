/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"testing"
)

// The NETCONF listener parses bytes from any TLS peer holding a client
// certificate (any certificate, unless -netconf-tls-client-ca is set), so
// its parsers must not panic or hang on what a peer sends.

func FuzzNetconfReader(f *testing.F) {
	f.Add([]byte("<hello/>]]>]]>"), false)
	f.Add([]byte("\n#4\n<rpc\n#2\n/>\n##\n"), true)
	f.Add([]byte("\n#4294967295\n"), true)
	f.Add([]byte("]]>]]]]>]]>"), false)
	f.Fuzz(func(t *testing.T, wire []byte, chunked bool) {
		r := newNetconfReader(bytes.NewReader(wire), 4096)
		r.chunked = chunked
		for i := 0; i < 8; i++ {
			msg, err := r.ReadMessage()
			if err != nil {
				return
			}
			if len(msg) > 4096 {
				t.Fatalf("message of %d bytes passed a 4096-byte limit", len(msg))
			}
		}
	})
}

// FuzzNetconfRequest drives what the dispatcher does with a message before
// any datastore is read: parse, filter conversion and XPath translation.
func FuzzNetconfRequest(f *testing.F) {
	f.Add([]byte(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><get><filter type="subtree"><interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface><name>a</name></interface></interfaces></filter></get></rpc>`))
	f.Add([]byte(`<x xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces">/if:interfaces/if:interface[if:name='a']/if:oper-status | /a</x>`))
	f.Add([]byte(`<!DOCTYPE a><a/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := parseNetconfXML(data)
		if err != nil {
			return
		}
		filter := subtreeFilterFromXML(root.Children)
		applyNetconfFilter(filterTestData(), filter, true)
		if nodes, err := xpathToSubtreeFilter(root.Text, root.Scope); err == nil {
			applyNetconfFilter(filterTestData(), nodes, true)
		}
	})
}
