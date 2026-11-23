package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func TestExecFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer

	startReq, _ := json.Marshal(ExecStartRequest{Command: "echo hi", Dir: "/tmp"})
	exitPayload, _ := json.Marshal(ExecExitPayload{Code: 7, Error: "boom"})

	cases := []struct {
		typ     byte
		payload []byte
	}{
		{ExecFrameStart, startReq},
		{ExecFrameStdin, []byte("input line\n")},
		{ExecFrameEOF, nil},
		{ExecFrameStdout, []byte("out data")},
		{ExecFrameStderr, []byte("err data")},
		{ExecFrameExit, exitPayload},
		{ExecFrameCancel, nil},
	}

	for _, tc := range cases {
		if err := WriteExecFrame(&buf, tc.typ, tc.payload); err != nil {
			t.Fatalf("WriteExecFrame(0x%02x) err: %v", tc.typ, err)
		}
	}

	for i, tc := range cases {
		gotTyp, gotPayload, err := ReadExecFrame(&buf)
		if err != nil {
			t.Fatalf("case %d ReadExecFrame err: %v", i, err)
		}
		if gotTyp != tc.typ {
			t.Fatalf("case %d type=%d want=%d", i, gotTyp, tc.typ)
		}
		if !bytes.Equal(gotPayload, tc.payload) {
			t.Fatalf("case %d payload=%q want=%q", i, gotPayload, tc.payload)
		}
	}

	if _, _, err := ReadExecFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF at end of stream, got %v", err)
	}
}

func TestExecFrameValidation(t *testing.T) {
	var buf bytes.Buffer
	oversize := make([]byte, MaxExecFrameBytes+1)
	if err := WriteExecFrame(&buf, ExecFrameStdout, oversize); err == nil {
		t.Fatalf("expected oversize WriteExecFrame error")
	}

	var hdr [5]byte
	hdr[0] = ExecFrameStdout
	binary.BigEndian.PutUint32(hdr[1:5], MaxExecFrameBytes+1)
	if _, _, err := ReadExecFrame(bytes.NewReader(hdr[:])); err == nil {
		t.Fatalf("expected oversize ReadExecFrame error")
	}

	// Truncated header
	if _, _, err := ReadExecFrame(bytes.NewReader([]byte{0x01, 0x00})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF for short header, got %v", err)
	}

	// Truncated payload
	binary.BigEndian.PutUint32(hdr[1:5], 10)
	truncated := append(hdr[:], []byte("123")...)
	if _, _, err := ReadExecFrame(bytes.NewReader(truncated)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF for truncated payload, got %v", err)
	}
}
