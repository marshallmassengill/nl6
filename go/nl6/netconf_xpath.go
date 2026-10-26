/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"strings"
)

// nl6 serves a SUBSET of XPath 1.0 in NETCONF filters, the subset collectors
// actually send for datastore selection, and refuses the rest by name rather
// than evaluating it wrongly:
//
//	expr      = path *( "|" path )
//	path      = 1*( "/" step )
//	step      = qname *predicate
//	predicate = "[" qname "=" literal "]"
//	qname     = [ prefix ":" ] name
//
// A path is translated into the equivalent subtree filter, so both filter
// types run through one engine and cannot disagree. Prefixes resolve through
// the xmlns declarations in scope at the filter element (RFC 6241 §8.9), and,
// as a convenience many clients rely on, a prefix that is the name of a
// module nl6 serves resolves to that module's namespace. An unprefixed name
// matches in any namespace.

// netconfXPathSubset names the supported grammar in error messages.
const netconfXPathSubset = "nl6 supports absolute location paths of child steps with [name='value'] predicates, joined by |"

// xpathToSubtreeFilter translates expr; scope is the prefix map of the
// element that carried it.
func xpathToSubtreeFilter(expr string, scope map[string]string) ([]*filterNode, error) {
	p := &xpathParser{s: expr, scope: scope}
	var out []*filterNode
	for {
		p.ws()
		root, err := p.path()
		if err != nil {
			return nil, err
		}
		out = append(out, root)
		p.ws()
		if p.eof() {
			return out, nil
		}
		if p.peek() != '|' {
			return nil, p.errf("unexpected %q", string(p.peek()))
		}
		p.i++
	}
}

type xpathParser struct {
	s     string
	i     int
	scope map[string]string
}

func (p *xpathParser) eof() bool  { return p.i >= len(p.s) }
func (p *xpathParser) peek() byte { return p.s[p.i] }

func (p *xpathParser) ws() {
	for !p.eof() && strings.IndexByte(" \t\r\n", p.peek()) >= 0 {
		p.i++
	}
}

func (p *xpathParser) errf(format string, args ...any) error {
	return fmt.Errorf("xpath %q at offset %d: %s (%s)", p.s, p.i, fmt.Sprintf(format, args...), netconfXPathSubset)
}

// path parses one location path and returns its first step, with the later
// steps nested below it.
func (p *xpathParser) path() (*filterNode, error) {
	var root, cur *filterNode
	for {
		p.ws()
		if p.eof() || p.peek() != '/' {
			if root == nil {
				return nil, p.errf("expected an absolute path starting with /")
			}
			return root, nil
		}
		p.i++
		if !p.eof() && p.peek() == '/' {
			return nil, p.errf("the descendant axis // is not supported")
		}
		ns, name, err := p.qname()
		if err != nil {
			return nil, err
		}
		step := &filterNode{NS: ns, Name: name}
		for {
			p.ws()
			if p.eof() || p.peek() != '[' {
				break
			}
			p.i++
			p.ws()
			kns, kname, err := p.qname()
			if err != nil {
				return nil, err
			}
			p.ws()
			if p.eof() || p.peek() != '=' {
				return nil, p.errf("only [name='value'] predicates are supported")
			}
			p.i++
			p.ws()
			lit, err := p.literal()
			if err != nil {
				return nil, err
			}
			p.ws()
			if p.eof() || p.peek() != ']' {
				return nil, p.errf("expected ]")
			}
			p.i++
			step.Children = append(step.Children, &filterNode{NS: kns, Name: kname, Match: lit, HasMatch: true})
		}
		if root == nil {
			root = step
		} else {
			cur.Children = append(cur.Children, step)
		}
		cur = step
	}
}

func isXPathNameChar(c byte, first bool) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		return true
	case !first && (c >= '0' && c <= '9' || c == '-' || c == '.'):
		return true
	}
	return false
}

func (p *xpathParser) ncname() (string, error) {
	start := p.i
	for !p.eof() && isXPathNameChar(p.peek(), p.i == start) {
		p.i++
	}
	if p.i == start {
		if !p.eof() && (p.peek() == '*' || p.peek() == '.' || p.peek() == '@') {
			return "", p.errf("wildcards, . and attributes are not supported")
		}
		return "", p.errf("expected a name")
	}
	return p.s[start:p.i], nil
}

// qname returns the namespace (empty for an unprefixed name) and local name.
func (p *xpathParser) qname() (string, string, error) {
	first, err := p.ncname()
	if err != nil {
		return "", "", err
	}
	if p.eof() || p.peek() != ':' {
		return "", first, nil
	}
	p.i++
	if !p.eof() && p.peek() == ':' {
		return "", "", p.errf("axes are not supported")
	}
	local, err := p.ncname()
	if err != nil {
		return "", "", err
	}
	if ns, ok := p.scope[first]; ok && first != "" {
		return ns, local, nil
	}
	if ns := netconfModuleNamespace(first); ns != "" {
		return ns, local, nil
	}
	return "", "", p.errf("prefix %q is not declared", first)
}

func (p *xpathParser) literal() (string, error) {
	if p.eof() || (p.peek() != '\'' && p.peek() != '"') {
		return "", p.errf("expected a quoted literal")
	}
	q := p.peek()
	p.i++
	end := strings.IndexByte(p.s[p.i:], q)
	if end < 0 {
		return "", p.errf("unterminated literal")
	}
	v := p.s[p.i : p.i+end]
	p.i += end + 1
	return v, nil
}
