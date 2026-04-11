// Package hmac provides HMAC-based integrity for Sidereal probe results.
//
// All cryptographic operations use stdlib crypto/hmac and crypto/sha256,
// which route to BoringCrypto when built with GOEXPERIMENT=boringcrypto
// for FIPS 140-2 compliance.
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	// ErrEmptyKey is returned when an empty root or execution key is provided.
	ErrEmptyKey = errors.New("hmac: key must not be empty")

	// ErrEmptyPayload is returned when an empty payload is provided for signing.
	ErrEmptyPayload = errors.New("hmac: payload must not be empty")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("hmac: signature verification failed")

	// ErrMalformedSignature is returned when a signature cannot be hex-decoded.
	ErrMalformedSignature = errors.New("hmac: malformed signature")
)

// DeriveExecutionKey derives a per-execution HMAC key from a root key using HKDF-SHA256.
// The probeID is used as the HKDF info parameter to bind the derived key to a specific execution.
func DeriveExecutionKey(rootKey []byte, probeID string) ([]byte, error) {
	if len(rootKey) == 0 {
		return nil, ErrEmptyKey
	}
	if probeID == "" {
		return nil, fmt.Errorf("hmac: probeID must not be empty")
	}

	hkdfReader := hkdf.New(sha256.New, rootKey, nil, []byte(probeID))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("hmac: key derivation failed: %w", err)
	}
	return derivedKey, nil
}

// SignResult computes an HMAC-SHA256 signature over the given payload.
// Returns the signature as a hex-encoded string.
func SignResult(key []byte, payload []byte) (string, error) {
	if len(key) == 0 {
		return "", ErrEmptyKey
	}
	if len(payload) == 0 {
		return "", ErrEmptyPayload
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyResult verifies an HMAC-SHA256 signature over the given payload.
// Uses constant-time comparison to prevent timing attacks.
func VerifyResult(key []byte, payload []byte, signature string) error {
	if len(key) == 0 {
		return ErrEmptyKey
	}
	if len(payload) == 0 {
		return ErrEmptyPayload
	}

	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return ErrMalformedSignature
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(sigBytes, expected) != 1 {
		return ErrInvalidSignature
	}
	return nil
}
