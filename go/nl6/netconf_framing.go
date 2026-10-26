/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// NETCONF message framing (RFC 6242 §4, which RFC 7589 §3 reuses for TLS).
//
// Two framings exist and a session switches between them exactly once: the
// hellos are always end-of-message framed, and chunked framing applies from
// the first message after them when BOTH peers advertised base:1.1. Reading
// chunked bytes as end-of-message (or the reverse) does not fail fast, it
// waits for a delimiter that never comes, so the switch lives in one place,
// the session's hello exchange.

// netconfEOM is the base:1.0 end-of-message delimiter.
const netconfEOM = "]]>]]>"

// errNetconfMessageTooLarge is returned when a message exceeds the reader's
// cap. The session cannot resynchronise after it (the rest of the message is
// still on the wire), so the caller closes the session.
var errNetconfMessageTooLarge = errors.New("netconf: message exceeds the size limit")

// errNetconfBadChunk is returned for a chunk header RFC 6242 §4.2 does not
// allow. Like an oversized message, it leaves the stream unframed.
var errNetconfBadChunk = errors.New("netconf: malformed chunk header")

// netconfReader reads framed messages from one session's stream.
type netconfReader struct {
	r       *bufio.Reader
	max     int
	chunked bool
}

func newNetconfReader(r io.Reader, max int) *netconfReader {
	return &netconfReader{r: bufio.NewReaderSize(r, 16*1024), max: max}
}

// ReadMessage returns the next message without its framing.
func (nr *netconfReader) ReadMessage() ([]byte, error) {
	if nr.chunked {
		return nr.readChunked()
	}
	return nr.readEOM()
}

// readEOM reads up to the end-of-message delimiter. The delimiter search
// looks only at the bytes a read appended plus the five before them, so a
// message costs one pass however it is split across reads.
func (nr *netconfReader) readEOM() ([]byte, error) {
	var buf []byte
	for {
		b, err := nr.r.ReadSlice('>')
		buf = append(buf, b...)
		if len(buf) > nr.max+len(netconfEOM) {
			return nil, errNetconfMessageTooLarge
		}
		if err == nil || errors.Is(err, bufio.ErrBufferFull) {
			if bytes.HasSuffix(buf, []byte(netconfEOM)) {
				return buf[:len(buf)-len(netconfEOM)], nil
			}
			continue
		}
		if errors.Is(err, io.EOF) && len(bytes.TrimSpace(buf)) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
}

// readChunked reads chunks until the end-of-chunks marker.
//
//	chunk         = LF HASH chunk-size LF chunk-data
//	end-of-chunks = LF HASH HASH LF
//	chunk-size    = 1-9 followed by up to nine DIGIT, max 4294967295
func (nr *netconfReader) readChunked() ([]byte, error) {
	var msg []byte
	for {
		if err := nr.expect('\n'); err != nil {
			return nil, err
		}
		if err := nr.expect('#'); err != nil {
			return nil, err
		}
		c, err := nr.r.ReadByte()
		if err != nil {
			return nil, err
		}
		if c == '#' {
			if err := nr.expect('\n'); err != nil {
				return nil, err
			}
			if len(msg) == 0 {
				// A message is at least one chunk; "\n##\n" alone is not one.
				return nil, errNetconfBadChunk
			}
			return msg, nil
		}
		if c < '1' || c > '9' {
			return nil, errNetconfBadChunk
		}
		digits := []byte{c}
		for {
			c, err = nr.r.ReadByte()
			if err != nil {
				return nil, err
			}
			if c == '\n' {
				break
			}
			if c < '0' || c > '9' || len(digits) == 10 {
				return nil, errNetconfBadChunk
			}
			digits = append(digits, c)
		}
		size, err := strconv.ParseUint(string(digits), 10, 64)
		if err != nil || size > 4294967295 {
			return nil, errNetconfBadChunk
		}
		if uint64(len(msg))+size > uint64(nr.max) {
			return nil, errNetconfMessageTooLarge
		}
		start := len(msg)
		msg = append(msg, make([]byte, size)...)
		if _, err := io.ReadFull(nr.r, msg[start:]); err != nil {
			return nil, err
		}
	}
}

func (nr *netconfReader) expect(want byte) error {
	c, err := nr.r.ReadByte()
	if err != nil {
		return err
	}
	if c != want {
		return fmt.Errorf("%w: got %q, want %q", errNetconfBadChunk, c, want)
	}
	return nil
}

// frameNetconfMessage returns msg with the framing of the session's current
// mode, as one buffer so a single Write puts it on the wire.
func frameNetconfMessage(msg []byte, chunked bool) []byte {
	if !chunked {
		out := make([]byte, 0, len(msg)+len(netconfEOM))
		out = append(out, msg...)
		return append(out, netconfEOM...)
	}
	header := "\n#" + strconv.Itoa(len(msg)) + "\n"
	out := make([]byte, 0, len(header)+len(msg)+4)
	out = append(out, header...)
	out = append(out, msg...)
	return append(out, "\n##\n"...)
}
