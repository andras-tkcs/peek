package server

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustHexSecret() string {
	b := make([]byte, 32)
	return hex.EncodeToString(b)
}

func TestSignVerifyRoundtrip(t *testing.T) {
	secret := mustHexSecret()
	slug := "abc123"
	exp := time.Now().Add(time.Hour).Unix()
	tok := signToken(secret, slug, exp)
	if !verifyToken(secret, tok, slug) {
		t.Fatalf("expected token to verify")
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	secret := mustHexSecret()
	slug := "abc123"
	exp := time.Now().Add(-time.Hour).Unix()
	tok := signToken(secret, slug, exp)
	if verifyToken(secret, tok, slug) {
		t.Fatalf("expected expired token to be rejected")
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	secret := mustHexSecret()
	slug := "abc123"
	exp := time.Now().Add(time.Hour).Unix()
	tok := signToken(secret, slug, exp)
	tok += "x"
	if verifyToken(secret, tok, slug) {
		t.Fatalf("expected tampered token to be rejected")
	}
}

func TestVerifyWrongSlug(t *testing.T) {
	secret := mustHexSecret()
	exp := time.Now().Add(time.Hour).Unix()
	tok := signToken(secret, "abc123", exp)
	if verifyToken(secret, tok, "xyz789") {
		t.Fatalf("expected token for different slug to be rejected")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	secret := mustHexSecret()
	plaintext := "my-super-secret-key"
	ciphertext, err := encryptSecret(secret, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := decryptSecret(secret, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plaintext {
		t.Fatalf("decrypt mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptSecretGCMFailureReturnsEmpty(t *testing.T) {
	secret1 := mustHexSecret()
	secret2 := strings.Repeat("f", 64)
	plaintext := "secret"
	ciphertext, err := encryptSecret(secret1, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := decryptSecret(secret2, ciphertext)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string on auth failure, got %q", got)
	}
}

func TestDecryptSecretEmpty(t *testing.T) {
	got, err := decryptSecret(mustHexSecret(), "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestDecryptSecretLegacyPlaintext(t *testing.T) {
	// Use a value that is not valid base64url so it falls through to the
	// legacy plaintext path.
	got, err := decryptSecret(mustHexSecret(), "plain text value")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "plain text value" {
		t.Fatalf("expected legacy plaintext to be returned as-is, got %q", got)
	}
}

func TestEncryptRequires32ByteKey(t *testing.T) {
	_, err := encryptSecret(strings.Repeat("a", 31), "x")
	if err == nil {
		t.Fatalf("expected error for non-hex key")
	}
	_, err = encryptSecret(hex.EncodeToString(make([]byte, 31)), "x")
	if err == nil {
		t.Fatalf("expected error for short key")
	}
}

func TestSecurityCovTokenParsing(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	if verifyToken(secret, "only.two", "slug") {
		t.Error("verifyToken accepted a two-part token")
	}
	if verifyViewToken(secret, "a.b.c", "a", "b") {
		t.Error("verifyViewToken accepted a three-part token")
	}
	if verifyViewToken(secret, "slug.vid.notanumber.sig", "slug", "vid") {
		t.Error("verifyViewToken accepted a non-numeric expiry")
	}
	if verifyViewToken(secret, "slug.vid.1.sig", "slug", "vid") {
		t.Error("verifyViewToken accepted an expired token")
	}
	good := makeViewToken(secret, "slug", "vid")
	if !verifyViewToken(secret, good, "slug", "vid") {
		t.Error("verifyViewToken rejected a fresh token")
	}
	if verifyViewToken(secret, good, "slug", "other") || verifyViewToken(secret, good, "slug", "") {
		t.Error("verifyViewToken accepted a different visitor")
	}
}

func TestSecurityCovSignedSubjectRejections(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	valid := makeWebSession(secret, "42", time.Hour)
	if sub, ok := parseSignedSubject(secret, valid); !ok || sub != "42" {
		t.Fatalf("valid session = %q, %v", sub, ok)
	}
	for name, val := range map[string]string{
		"empty":      "",
		"one part":   "42",
		"two parts":  "42.123",
		"bad hmac":   "42.99999999999." + strings.Repeat("0", 64),
		"bad expiry": "42.abc." + strings.Repeat("0", 64),
		"expired":    makeWebSession(secret, "42", -time.Hour),
		"tampered":   strings.Replace(valid, "42", "43", 1),
	} {
		if _, ok := parseSignedSubject(secret, val); ok {
			t.Errorf("%s: parseSignedSubject accepted %q", name, val)
		}
	}
}

func TestSecurityCovEncryptDecryptEdgeCases(t *testing.T) {
	key := strings.Repeat("ab", 32)
	stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand failed") })
	if _, err := encryptSecret(key, "x"); err == nil {
		t.Error("encryptSecret ignored a nonce failure")
	}
	// A valid base64 string shorter than the GCM nonce is treated as legacy plaintext.
	if got, err := decryptSecret(key, "abc"); err != nil || got != "abc" {
		t.Errorf("decryptSecret short = %q, %v", got, err)
	}
	if got, err := decryptSecret(key, "not base64 !!"); err != nil || got != "not base64 !!" {
		t.Errorf("decryptSecret legacy = %q, %v", got, err)
	}
	if _, err := decryptSecret("zz", "abc"); err == nil {
		t.Error("decryptSecret accepted an invalid key")
	}
}
