/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestNetconfFramingRoundTrip(t *testing.T) {
	msgs := []string{"<a/>", strings.Repeat("x", 40000), "<b>]]></b>"}
	for _, chunked := range []bool{false, true} {
		var wire bytes.Buffer
		for _, m := range msgs {
			if !chunked && strings.Contains(m, netconfEOM) {
				continue
			}
			wire.Write(frameNetconfMessage([]byte(m), chunked))
		}
		// One byte per read: the delimiter and chunk headers split everywhere.
		r := newNetconfReader(iotest.OneByteReader(&wire), 1<<20)
		r.chunked = chunked
		for _, m := range msgs {
			if !chunked && strings.Contains(m, netconfEOM) {
				continue
			}
			got, err := r.ReadMessage()
			if err != nil {
				t.Fatalf("chunked=%v: %v", chunked, err)
			}
			if string(got) != m {
				t.Fatalf("chunked=%v: got %d bytes, want %d", chunked, len(got), len(m))
			}
		}
		if _, err := r.ReadMessage(); !errors.Is(err, io.EOF) {
			t.Fatalf("chunked=%v: after the last message: %v", chunked, err)
		}
	}
}

func TestNetconfChunkedAcceptsSeveralChunks(t *testing.T) {
	r := newNetconfReader(strings.NewReader("\n#4\n<rpc\n#17\n message-id=\"1\"/>\n##\n"), 1<<20)
	r.chunked = true
	got, err := r.ReadMessage()
	if err != nil || string(got) != `<rpc message-id="1"/>` {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNetconfChunkedRejectsMalformedHeaders(t *testing.T) {
	for name, wire := range map[string]string{
		"leading zero":   "\n#01\nx\n##\n",
		"zero size":      "\n#0\n\n##\n",
		"eleven digits":  "\n#12345678901\nx\n##\n",
		"too large":      "\n#4294967296\nx\n##\n",
		"no LF":          "#1\nx\n##\n",
		"empty message":  "\n##\n",
		"letter in size": "\n#1a\nx\n##\n",
	} {
		r := newNetconfReader(strings.NewReader(wire), 1<<20)
		r.chunked = true
		if _, err := r.ReadMessage(); !errors.Is(err, errNetconfBadChunk) {
			t.Errorf("%s: err %v, want errNetconfBadChunk", name, err)
		}
	}
}

func TestNetconfReaderEnforcesTheSizeLimit(t *testing.T) {
	big := strings.Repeat("y", 2000)
	r := newNetconfReader(strings.NewReader(big+netconfEOM), 1000)
	if _, err := r.ReadMessage(); !errors.Is(err, errNetconfMessageTooLarge) {
		t.Errorf("end-of-message: %v", err)
	}
	r = newNetconfReader(bytes.NewReader(frameNetconfMessage([]byte(big), true)), 1000)
	r.chunked = true
	if _, err := r.ReadMessage(); !errors.Is(err, errNetconfMessageTooLarge) {
		t.Errorf("chunked: %v", err)
	}
	// The limit is on the message, not the frame: exactly max passes.
	r = newNetconfReader(strings.NewReader(big[:1000]+netconfEOM), 1000)
	if _, err := r.ReadMessage(); err != nil {
		t.Errorf("a message of exactly the limit: %v", err)
	}
}

func TestNetconfTruncatedMessageIsNotEOF(t *testing.T) {
	r := newNetconfReader(strings.NewReader("<rpc message-id=\"1\">"), 1<<20)
	if _, err := r.ReadMessage(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("got %v, want io.ErrUnexpectedEOF", err)
	}
}
