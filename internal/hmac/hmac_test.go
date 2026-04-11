package hmac

import (
	"crypto/rand"
	"strings"
	"testing"
)

func generateRootKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	return key
}

func TestDeriveExecutionKey(t *testing.T) {
	rootKey := generateRootKey(t)

	t.Run("derives a 32-byte key", func(t *testing.T) {
		key, err := DeriveExecutionKey(rootKey, "probe-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(key) != 32 {
			t.Errorf("expected 32-byte key, got %d bytes", len(key))
		}
	})

	t.Run("same inputs produce same key", func(t *testing.T) {
		k1, _ := DeriveExecutionKey(rootKey, "probe-123")
		k2, _ := DeriveExecutionKey(rootKey, "probe-123")
		if string(k1) != string(k2) {
			t.Error("same inputs should produce same derived key")
		}
	})

	t.Run("different probeIDs produce different keys", func(t *testing.T) {
		k1, _ := DeriveExecutionKey(rootKey, "probe-123")
		k2, _ := DeriveExecutionKey(rootKey, "probe-456")
		if string(k1) == string(k2) {
			t.Error("different probeIDs should produce different derived keys")
		}
	})

	t.Run("different root keys produce different keys", func(t *testing.T) {
		otherRoot := generateRootKey(t)
		k1, _ := DeriveExecutionKey(rootKey, "probe-123")
		k2, _ := DeriveExecutionKey(otherRoot, "probe-123")
		if string(k1) == string(k2) {
			t.Error("different root keys should produce different derived keys")
		}
	})

	t.Run("empty root key returns error", func(t *testing.T) {
		_, err := DeriveExecutionKey([]byte{}, "probe-123")
		if err != ErrEmptyKey {
			t.Errorf("expected ErrEmptyKey, got: %v", err)
		}
	})

	t.Run("nil root key returns error", func(t *testing.T) {
		_, err := DeriveExecutionKey(nil, "probe-123")
		if err != ErrEmptyKey {
			t.Errorf("expected ErrEmptyKey, got: %v", err)
		}
	})

	t.Run("empty probeID returns error", func(t *testing.T) {
		_, err := DeriveExecutionKey(rootKey, "")
		if err == nil {
			t.Error("expected error for empty probeID")
		}
	})
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	rootKey := generateRootKey(t)
	execKey, _ := DeriveExecutionKey(rootKey, "probe-roundtrip")
	payload := []byte(`{"outcome":"Pass","probeType":"rbac","targetNamespace":"production"}`)

	sig, err := SignResult(execKey, payload)
	if err != nil {
		t.Fatalf("SignResult failed: %v", err)
	}

	if sig == "" {
		t.Fatal("signature should not be empty")
	}

	// Should be 64 hex chars (32 bytes)
	if len(sig) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(sig))
	}

	if err := VerifyResult(execKey, payload, sig); err != nil {
		t.Errorf("VerifyResult should succeed for valid signature: %v", err)
	}
}

func TestVerifyDetectsTamperedPayload(t *testing.T) {
	rootKey := generateRootKey(t)
	execKey, _ := DeriveExecutionKey(rootKey, "probe-tamper")
	payload := []byte(`{"outcome":"Pass"}`)

	sig, _ := SignResult(execKey, payload)

	tampered := []byte(`{"outcome":"Fail"}`)
	if err := VerifyResult(execKey, tampered, sig); err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for tampered payload, got: %v", err)
	}
}

func TestVerifyDetectsKeyMismatch(t *testing.T) {
	rootKey := generateRootKey(t)
	key1, _ := DeriveExecutionKey(rootKey, "probe-1")
	key2, _ := DeriveExecutionKey(rootKey, "probe-2")
	payload := []byte(`{"outcome":"Pass"}`)

	sig, _ := SignResult(key1, payload)

	if err := VerifyResult(key2, payload, sig); err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for key mismatch, got: %v", err)
	}
}

func TestVerifyDetectsMalformedSignature(t *testing.T) {
	rootKey := generateRootKey(t)
	execKey, _ := DeriveExecutionKey(rootKey, "probe-malformed")
	payload := []byte(`{"outcome":"Pass"}`)

	if err := VerifyResult(execKey, payload, "not-hex!@#$"); err != ErrMalformedSignature {
		t.Errorf("expected ErrMalformedSignature, got: %v", err)
	}
}

func TestVerifyDetectsTruncatedSignature(t *testing.T) {
	rootKey := generateRootKey(t)
	execKey, _ := DeriveExecutionKey(rootKey, "probe-truncated")
	payload := []byte(`{"outcome":"Pass"}`)

	sig, _ := SignResult(execKey, payload)
	truncated := sig[:len(sig)-4]

	if err := VerifyResult(execKey, payload, truncated); err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for truncated signature, got: %v", err)
	}
}

func TestSignEmptyInputs(t *testing.T) {
	rootKey := generateRootKey(t)
	execKey, _ := DeriveExecutionKey(rootKey, "probe-empty")

	t.Run("empty key", func(t *testing.T) {
		_, err := SignResult([]byte{}, []byte("payload"))
		if err != ErrEmptyKey {
			t.Errorf("expected ErrEmptyKey, got: %v", err)
		}
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := SignResult(nil, []byte("payload"))
		if err != ErrEmptyKey {
			t.Errorf("expected ErrEmptyKey, got: %v", err)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		_, err := SignResult(execKey, []byte{})
		if err != ErrEmptyPayload {
			t.Errorf("expected ErrEmptyPayload, got: %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		_, err := SignResult(execKey, nil)
		if err != ErrEmptyPayload {
			t.Errorf("expected ErrEmptyPayload, got: %v", err)
		}
	})
}

func TestVerifyEmptyInputs(t *testing.T) {
	t.Run("empty key", func(t *testing.T) {
		err := VerifyResult([]byte{}, []byte("payload"), "aabbccdd")
		if err != ErrEmptyKey {
			t.Errorf("expected ErrEmptyKey, got: %v", err)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		err := VerifyResult([]byte("key"), []byte{}, "aabbccdd")
		if err != ErrEmptyPayload {
			t.Errorf("expected ErrEmptyPayload, got: %v", err)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		err := VerifyResult([]byte("key"), []byte("payload"), "")
		if err != ErrInvalidSignature {
			t.Errorf("expected ErrInvalidSignature for empty signature, got: %v", err)
		}
	})
}

func TestSignatureIsHexEncoded(t *testing.T) {
	rootKey := generateRootKey(t)
	execKey, _ := DeriveExecutionKey(rootKey, "probe-hex")

	sig, _ := SignResult(execKey, []byte("test payload"))

	for _, c := range sig {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("signature contains non-hex character: %c", c)
			break
		}
	}
}
