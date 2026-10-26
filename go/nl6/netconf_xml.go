/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The NETCONF server's two XML shapes: xmlElem is what a client SENT (an rpc,
// a filter), parsed with every namespace resolved; ncNode is what nl6 SERVES
// (a datastore tree, a notification body), written by hand so the namespace
// of every element is decided by the data model rather than by whatever
// encoding/xml's marshaller infers.

// Namespaces the server reads or writes.
const (
	nsNetconfBase     = "urn:ietf:params:xml:ns:netconf:base:1.0"
	nsNetconfNotif    = "urn:ietf:params:xml:ns:netconf:notification:1.0"
	nsNetconfNMDA     = "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"
	nsDatastores      = "urn:ietf:params:xml:ns:yang:ietf-datastores"
	nsSubscribedNotif = "urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
	nsYangPush        = "urn:ietf:params:xml:ns:yang:ietf-yang-push"
	nsYangLibrary     = "urn:ietf:params:xml:ns:yang:ietf-yang-library"
	nsIETFInterfaces  = "urn:ietf:params:xml:ns:yang:ietf-interfaces"
	nsIANAIfType      = "urn:ietf:params:xml:ns:yang:iana-if-type"
)

// netconfMaxXMLDepth bounds element nesting in anything a client sends. The
// deepest legitimate input is a subtree filter over a model a few levels
// deep; the bound stops a crafted message from recursing the filter engine.
const netconfMaxXMLDepth = 64

// xmlElem is one parsed element of a client message.
type xmlElem struct {
	Space, Local string
	Attrs        []xml.Attr // xmlns declarations excluded
	// Scope maps every prefix in scope at this element to its namespace, so
	// an XPath expression in an attribute or text node can resolve its
	// prefixes the way the client declared them.
	Scope    map[string]string
	Children []*xmlElem
	Text     string // character data directly inside the element, trimmed
}

// Child returns the first child element with the given namespace and name.
func (e *xmlElem) Child(space, local string) *xmlElem {
	for _, c := range e.Children {
		if c.Local == local && c.Space == space {
			return c
		}
	}
	return nil
}

// Attr returns the value of an unqualified attribute.
func (e *xmlElem) Attr(local string) (string, bool) {
	for _, a := range e.Attrs {
		if a.Name.Space == "" && a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

var errNetconfXMLDirective = errors.New("DTDs and other directives are not accepted")

// parseNetconfXML parses one message into its root element. It refuses DTDs
// outright (encoding/xml expands no external entities, but a DOCTYPE has no
// legitimate place in NETCONF), bounds the depth, and resolves every prefix.
func parseNetconfXML(data []byte) (*xmlElem, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	var stack []*xmlElem
	var root *xmlElem
	// Pointers: a strings.Builder must not be copied once written to, and
	// append copies the slice's elements when it grows.
	var text []*strings.Builder
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if root != nil && len(stack) == 0 {
				return nil, fmt.Errorf("more than one root element")
			}
			if len(stack) >= netconfMaxXMLDepth {
				return nil, fmt.Errorf("elements nested deeper than %d", netconfMaxXMLDepth)
			}
			scope := map[string]string{}
			if len(stack) > 0 {
				for k, v := range stack[len(stack)-1].Scope {
					scope[k] = v
				}
			}
			el := &xmlElem{Space: t.Name.Space, Local: t.Name.Local, Scope: scope}
			for _, a := range t.Attr {
				switch {
				case a.Name.Space == "xmlns":
					scope[a.Name.Local] = a.Value
				case a.Name.Space == "" && a.Name.Local == "xmlns":
					scope[""] = a.Value
				default:
					el.Attrs = append(el.Attrs, a)
				}
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, el)
			} else {
				root = el
			}
			stack = append(stack, el)
			text = append(text, &strings.Builder{})
		case xml.EndElement:
			el := stack[len(stack)-1]
			el.Text = strings.TrimSpace(text[len(text)-1].String())
			stack = stack[:len(stack)-1]
			text = text[:len(text)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if len(bytes.TrimSpace(t)) > 0 {
					return nil, fmt.Errorf("character data outside the root element")
				}
				continue
			}
			text[len(text)-1].Write(t)
		case xml.Directive:
			return nil, errNetconfXMLDirective
		}
	}
	if root == nil {
		return nil, fmt.Errorf("no root element")
	}
	return root, nil
}

// ncNode is one node of served data: a leaf (Value set, no Children) or an
// interior node. NS is the node's module namespace; the writer declares it
// only where it differs from the parent's, which is the canonical form RFC
// 7950 §7 examples use.
type ncNode struct {
	NS       string
	Name     string
	Value    string
	Leaf     bool
	Children []*ncNode
	// ValuePrefix/ValueNS declare a prefix the value uses, for identityref
	// leaves such as iana-if-type's `ianaift:ethernetCsmacd`.
	ValuePrefix, ValueNS string
	// orig is the served node a filtered copy was taken from, so two filter
	// branches selecting the same node can be merged instead of duplicated.
	orig *ncNode
}

func ncLeaf(ns, name, value string) *ncNode {
	return &ncNode{NS: ns, Name: name, Value: value, Leaf: true}
}

func ncContainer(ns, name string, children ...*ncNode) *ncNode {
	return &ncNode{NS: ns, Name: name, Children: children}
}

// writeNetconfNodes appends nodes as XML whose enclosing element is in parentNS.
func writeNetconfNodes(b *bytes.Buffer, nodes []*ncNode, parentNS string) {
	for _, n := range nodes {
		writeNetconfNode(b, n, parentNS)
	}
}

func writeNetconfNode(b *bytes.Buffer, n *ncNode, parentNS string) {
	b.WriteByte('<')
	b.WriteString(n.Name)
	if n.NS != parentNS {
		b.WriteString(` xmlns="`)
		xmlEscapeAttr(b, n.NS)
		b.WriteByte('"')
	}
	if n.ValuePrefix != "" {
		b.WriteString(` xmlns:`)
		b.WriteString(n.ValuePrefix)
		b.WriteString(`="`)
		xmlEscapeAttr(b, n.ValueNS)
		b.WriteByte('"')
	}
	if n.Leaf {
		if n.Value == "" {
			b.WriteString("/>")
			return
		}
		b.WriteByte('>')
		_ = xml.EscapeText(b, []byte(n.Value))
	} else {
		b.WriteByte('>')
		writeNetconfNodes(b, n.Children, n.NS)
	}
	b.WriteString("</")
	b.WriteString(n.Name)
	b.WriteByte('>')
}

func xmlEscapeAttr(b *bytes.Buffer, s string) {
	_ = xml.EscapeText(b, []byte(s)) // escapes the quote as well
}

func xmlEscapeString(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// filterNode is one node of a subtree filter, from either a <filter
// type="subtree"> body or a translated XPath expression. An empty NS matches
// any namespace, which is what an element with xmlns="" means in a subtree
// filter (RFC 6241 §6.2.2).
type filterNode struct {
	NS, Name string
	// Match is the content-match value; HasMatch distinguishes an empty
	// element (a selection node) from one whose text is the empty string.
	Match    string
	HasMatch bool
	Children []*filterNode
}

func (f *filterNode) matchesName(n *ncNode) bool {
	return f.Name == n.Name && (f.NS == "" || f.NS == n.NS)
}

func (f *filterNode) isContentMatch() bool { return f.HasMatch && len(f.Children) == 0 }
func (f *filterNode) isSelection() bool    { return !f.HasMatch && len(f.Children) == 0 }

// subtreeFilterFromXML converts the children of a <filter>,
// <subtree-filter> or <datastore-subtree-filter> element.
func subtreeFilterFromXML(elems []*xmlElem) []*filterNode {
	out := make([]*filterNode, 0, len(elems))
	for _, e := range elems {
		f := &filterNode{NS: e.Space, Name: e.Local}
		if len(e.Children) == 0 && e.Text != "" {
			f.Match, f.HasMatch = e.Text, true
		}
		f.Children = subtreeFilterFromXML(e.Children)
		out = append(out, f)
	}
	return out
}

// applyNetconfFilter selects from the top-level data nodes. A nil filter
// selects everything; an empty one (a filter element with no children)
// selects nothing, as RFC 6241 §6.4.2 specifies.
func applyNetconfFilter(data []*ncNode, filter []*filterNode, filtered bool) []*ncNode {
	if !filtered {
		return data
	}
	if len(filter) == 0 {
		return nil
	}
	out, _ := filterLevel(data, filter)
	return out
}

// filterLevel applies the filter nodes of one level to the sibling data nodes
// of one parent instance (RFC 6241 §6.2). ok is false when a content-match
// node fails, which excludes the parent instance.
func filterLevel(data []*ncNode, filter []*filterNode) (out []*ncNode, ok bool) {
	var matches, others []*filterNode
	for _, f := range filter {
		if f.isContentMatch() {
			matches = append(matches, f)
		} else {
			others = append(others, f)
		}
	}
	for _, m := range matches {
		found := false
		for _, d := range data {
			if d.Leaf && m.matchesName(d) && d.Value == m.Match {
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	if len(others) == 0 {
		// Only content-match nodes: the whole instance is selected.
		return data, true
	}
	for _, d := range data {
		matched := false
		for _, m := range matches {
			if d.Leaf && m.matchesName(d) {
				matched = true
				break
			}
		}
		if matched {
			out = append(out, d)
			continue
		}
		var result *ncNode
		for _, f := range others {
			if !f.matchesName(d) {
				continue
			}
			if f.isSelection() || d.Leaf {
				if f.isSelection() {
					result = d
					break
				}
				continue
			}
			sub, subOK := filterLevel(d.Children, f.Children)
			if !subOK || len(sub) == 0 {
				continue
			}
			copyNode := &ncNode{NS: d.NS, Name: d.Name, Children: sub, orig: d}
			if result == nil {
				result = copyNode
			} else {
				result = mergeFilteredNodes(result, copyNode)
			}
		}
		if result != nil {
			out = append(out, result)
		}
	}
	return out, true
}

// mergeFilteredNodes unions two filtered copies of the same served node,
// keeping the served child order.
func mergeFilteredNodes(a, b *ncNode) *ncNode {
	if a.orig == nil {
		return a // a is the whole node already
	}
	if b.orig == nil {
		return b
	}
	byOrig := map[*ncNode]*ncNode{}
	for _, c := range a.Children {
		byOrig[origOf(c)] = c
	}
	for _, c := range b.Children {
		if prev, ok := byOrig[origOf(c)]; ok {
			if prev != c {
				byOrig[origOf(c)] = mergeFilteredNodes(prev, c)
			}
			continue
		}
		byOrig[origOf(c)] = c
	}
	merged := &ncNode{NS: a.NS, Name: a.Name, orig: a.orig}
	for _, c := range a.orig.Children {
		if n, ok := byOrig[c]; ok {
			merged.Children = append(merged.Children, n)
		}
	}
	return merged
}

func origOf(n *ncNode) *ncNode {
	if n.orig != nil {
		return n.orig
	}
	return n
}
