/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"strings"
	"testing"
)

// filterTestData is RFC 6241 §6.4's users example, in the shape the filter
// engine sees: one top-level container holding a keyed list.
func filterTestData() []*ncNode {
	const ns = "urn:example:users"
	user := func(name, typ, full string) *ncNode {
		return ncContainer(ns, "user", ncLeaf(ns, "name", name), ncLeaf(ns, "type", typ), ncLeaf(ns, "full-name", full))
	}
	return []*ncNode{
		ncContainer(ns, "users", user("root", "superuser", "Charlie Root"), user("fred", "admin", "Fred Flintstone"), user("barney", "admin", "Barney Rubble")),
		ncContainer("urn:example:other", "system", ncLeaf("urn:example:other", "hostname", "nl6")),
	}
}

func renderFiltered(t *testing.T, filterXML string) string {
	t.Helper()
	el, err := parseNetconfXML([]byte("<filter>" + filterXML + "</filter>"))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	writeNetconfNodes(&b, applyNetconfFilter(filterTestData(), subtreeFilterFromXML(el.Children), true), "")
	return b.String()
}

func TestNetconfSubtreeFilterSemantics(t *testing.T) {
	const u = `xmlns="urn:example:users"`
	for _, tc := range []struct {
		name, filter, want string
	}{
		{"empty filter selects nothing", ``, ``},
		{"selection node selects the subtree", `<system xmlns="urn:example:other"/>`,
			`<system xmlns="urn:example:other"><hostname>nl6</hostname></system>`},
		{"content match alone selects whole entries", `<users ` + u + `><user><name>fred</name></user></users>`,
			`<users ` + u + `><user><name>fred</name><type>admin</type><full-name>Fred Flintstone</full-name></user></users>`},
		{"content match plus selection", `<users ` + u + `><user><name>fred</name><type/></user></users>`,
			`<users ` + u + `><user><name>fred</name><type>admin</type></user></users>`},
		{"content match on a non-key leaf", `<users ` + u + `><user><type>admin</type><name/></user></users>`,
			`<users ` + u + `><user><name>fred</name><type>admin</type></user><user><name>barney</name><type>admin</type></user></users>`},
		{"wrong namespace selects nothing", `<users xmlns="urn:example:wrong"/>`, ``},
		{"no namespace matches any", `<system xmlns=""><hostname/></system>`,
			`<system xmlns="urn:example:other"><hostname>nl6</hostname></system>`},
		{"two containment nodes merge in data order", `<users ` + u + `><user><name>barney</name><type/></user><user><name>barney</name><full-name/></user></users>`,
			`<users ` + u + `><user><name>barney</name><type>admin</type><full-name>Barney Rubble</full-name></user></users>`},
		{"unmatched content selects nothing", `<users ` + u + `><user><name>wilma</name></user></users>`, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderFiltered(t, tc.filter); got != tc.want {
				t.Errorf("\ngot  %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestNetconfNoFilterSelectsEverything(t *testing.T) {
	data := filterTestData()
	if got := applyNetconfFilter(data, nil, false); len(got) != len(data) {
		t.Fatalf("got %d nodes", len(got))
	}
}

func TestNetconfXPathTranslatesToTheEquivalentSubtreeFilter(t *testing.T) {
	scope := map[string]string{"u": "urn:example:users"}
	for _, tc := range []struct{ xpath, subtree string }{
		{`/u:users/u:user[u:name='fred']/u:type`, `<users xmlns="urn:example:users"><user><name>fred</name><type/></user></users>`},
		{`/u:users/u:user[u:name="fred"]`, `<users xmlns="urn:example:users"><user><name>fred</name></user></users>`},
		{` /users/user[name = 'barney'] | /u:users/u:user[u:name='root']/u:full-name `,
			`<users><user><name>barney</name></user></users><users xmlns="urn:example:users"><user><name>root</name><full-name/></user></users>`},
	} {
		nodes, err := xpathToSubtreeFilter(tc.xpath, scope)
		if err != nil {
			t.Fatalf("%s: %v", tc.xpath, err)
		}
		var got, want bytes.Buffer
		writeNetconfNodes(&got, applyNetconfFilter(filterTestData(), nodes, true), "")
		writeNetconfNodes(&want, applyNetconfFilter(filterTestData(), parseFilterForTest(t, tc.subtree), true), "")
		if got.String() != want.String() || got.Len() == 0 {
			t.Errorf("%s:\ngot  %s\nwant %s", tc.xpath, got.String(), want.String())
		}
	}
}

func parseFilterForTest(t *testing.T, s string) []*filterNode {
	t.Helper()
	el, err := parseNetconfXML([]byte("<filter>" + s + "</filter>"))
	if err != nil {
		t.Fatal(err)
	}
	return subtreeFilterFromXML(el.Children)
}

func TestNetconfXPathRefusesOutsideTheSubset(t *testing.T) {
	for _, x := range []string{
		`users`, `//user`, `/users/*`, `/users/user[1]`, `/users/user[name!='x']`, `/users/user/@id`,
		`/u:users/x:user`, `/users/user[name='x'`, `/users/user[name='x]`, `/child::users`,
	} {
		if _, err := xpathToSubtreeFilter(x, map[string]string{"u": "urn:example:users"}); err == nil {
			t.Errorf("%q accepted", x)
		} else if !strings.Contains(err.Error(), "nl6 supports") {
			t.Errorf("%q: error does not state the subset: %v", x, err)
		}
	}
}

func TestNetconfXMLParserRefusesDTDsAndDepth(t *testing.T) {
	if _, err := parseNetconfXML([]byte(`<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>`)); err == nil {
		t.Error("a DTD was accepted")
	}
	deep := strings.Repeat("<a>", netconfMaxXMLDepth+1) + strings.Repeat("</a>", netconfMaxXMLDepth+1)
	if _, err := parseNetconfXML([]byte(deep)); err == nil {
		t.Error("nesting beyond the bound was accepted")
	}
	if _, err := parseNetconfXML([]byte(`<a/><b/>`)); err == nil {
		t.Error("two roots were accepted")
	}
}

func TestRestconfKeyEscape(t *testing.T) {
	for in, want := range map[string]string{
		"eth0":               "eth0",
		"GigabitEthernet0/1": "GigabitEthernet0%2F1",
		"ge-0/0/0.100":       "ge-0%2F0%2F0.100",
		"a b,c=d":            "a%20b%2Cc%3Dd",
	} {
		if got := restconfKeyEscape(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
