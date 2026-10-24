package beacon

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenRoundTripAndFixedSize(t *testing.T) {
	psk, _ := NewPSK()
	for _, payload := range [][]byte{
		[]byte("ping"),
		[]byte(`{"cmd":"whoami"}`),
		bytes.Repeat([]byte("x"), MaxPayload),
	} {
		frame, err := Seal(psk, 1, payload)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if len(frame) != Size {
			t.Fatalf("frame size = %d, want %d", len(frame), Size)
		}
		got, seq, err := Open(psk, frame, 0)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if seq != 1 {
			t.Errorf("seq = %d", seq)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("payload round-trip mismatch: %q", got)
		}
	}
}

func TestFramesAreIndistinguishableBySize(t *testing.T) {
	psk, _ := NewPSK()
	empty, _ := Seal(psk, 1, nil)
	full, _ := Seal(psk, 2, bytes.Repeat([]byte("a"), MaxPayload))
	if len(empty) != len(full) {
		t.Fatalf("idle and full frames differ in size: %d vs %d", len(empty), len(full))
	}
}

func TestOpenRejectsReplayAndReorder(t *testing.T) {
	psk, _ := NewPSK()
	frame, _ := Seal(psk, 5, []byte("cmd"))
	if _, _, err := Open(psk, frame, 5); !errors.Is(err, ErrReplay) {
		t.Fatalf("seq == lastSeq: got %v, want ErrReplay", err)
	}
	if _, _, err := Open(psk, frame, 9); !errors.Is(err, ErrReplay) {
		t.Fatalf("older seq: got %v, want ErrReplay", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	psk, _ := NewPSK()
	frame, _ := Seal(psk, 1, []byte("cmd"))
	frame[headerLen+2] ^= 0xff // flip a ciphertext byte
	if _, _, err := Open(psk, frame, 0); err == nil {
		t.Fatal("tampered frame must fail")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	psk, _ := NewPSK()
	other, _ := NewPSK()
	frame, _ := Seal(psk, 1, []byte("cmd"))
	if _, _, err := Open(other, frame, 0); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestOpenRejectsShortFrame(t *testing.T) {
	psk, _ := NewPSK()
	if _, _, err := Open(psk, make([]byte, Size-1), 0); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("got %v, want ErrShortFrame", err)
	}
}

func TestSealRejectsOversize(t *testing.T) {
	psk, _ := NewPSK()
	if _, err := Seal(psk, 1, make([]byte, MaxPayload+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestSeqIsBoundAsAAD(t *testing.T) {
	// Rewriting the sequence number must invalidate the AEAD tag.
	psk, _ := NewPSK()
	frame, _ := Seal(psk, 1, []byte("cmd"))
	frame[7] = 2 // seq 1 -> 2
	if _, _, err := Open(psk, frame, 0); err == nil {
		t.Fatal("renumbered frame must fail (seq must be authenticated)")
	}
}
