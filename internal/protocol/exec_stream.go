package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	ExecFrameStart  byte = 0x00 // Client -> Agent: JSON ExecStartRequest
	ExecFrameStdin  byte = 0x01 // Client -> Agent: raw stdin bytes
	ExecFrameEOF    byte = 0x02 // Client -> Agent: stdin EOF (empty payload)
	ExecFrameStdout byte = 0x03 // Agent -> Client: raw stdout bytes
	ExecFrameStderr byte = 0x04 // Agent -> Client: raw stderr bytes
	ExecFrameExit   byte = 0x05 // Agent -> Client: JSON ExecExitPayload
	ExecFrameCancel byte = 0x06 // Client -> Agent: cancel/kill remote process (empty payload)

	MaxExecFrameBytes = 1 << 20 // 1 MiB per frame
)

type ExecStartRequest struct {
	Command string `json:"command"`
	Dir     string `json:"dir,omitempty"`
}

type ExecExitPayload struct {
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

// WriteExecFrame writes a single framed exec control/data message:
// [1-byte frameType][4-byte big-endian payload length][payload].
func WriteExecFrame(w io.Writer, frameType byte, payload []byte) error {
	if len(payload) > MaxExecFrameBytes {
		return fmt.Errorf("exec frame payload too large (%d bytes)", len(payload))
	}
	buf := make([]byte, 5+len(payload))
	buf[0] = frameType
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadExecFrame reads a single framed exec control/data message.
func ReadExecFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > MaxExecFrameBytes {
		return 0, nil, fmt.Errorf("exec frame payload too large (%d bytes)", n)
	}
	if n == 0 {
		return hdr[0], nil, nil
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}
