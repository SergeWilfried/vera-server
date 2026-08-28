package main

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// cborEncode helpers for tests only — build the exact subset the decoder reads.
func cborUint(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}

func cborText(s string) []byte  { return append(cborUint(3, len(s)), s...) }
func cborBytes(b []byte) []byte { return append(cborUint(2, len(b)), b...) }

func TestCborDecodeAttestationShape(t *testing.T) {
	authData := bytes.Repeat([]byte{0xAB}, 60)
	cred := []byte{1, 2, 3}
	ca := []byte{4, 5}
	obj := []byte{}
	obj = append(obj, cborUint(5, 3)...) // map(3)
	obj = append(obj, cborText("fmt")...)
	obj = append(obj, cborText("apple-appattest")...)
	obj = append(obj, cborText("attStmt")...)
	obj = append(obj, cborUint(5, 2)...) // map(2)
	obj = append(obj, cborText("x5c")...)
	obj = append(obj, cborUint(4, 2)...) // array(2)
	obj = append(obj, cborBytes(cred)...)
	obj = append(obj, cborBytes(ca)...)
	obj = append(obj, cborText("receipt")...)
	obj = append(obj, cborBytes([]byte{9})...)
	obj = append(obj, cborText("authData")...)
	obj = append(obj, cborBytes(authData)...)

	v, err := cborDecode(obj)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := v.(map[string]any)
	if m["fmt"] != "apple-appattest" {
		t.Fatalf("fmt = %v", m["fmt"])
	}
	x5c := m["attStmt"].(map[string]any)["x5c"].([]any)
	if !bytes.Equal(x5c[0].([]byte), cred) || !bytes.Equal(x5c[1].([]byte), ca) {
		t.Fatal("x5c mismatch")
	}
	if !bytes.Equal(m["authData"].([]byte), authData) {
		t.Fatal("authData mismatch")
	}
}

func TestCborDecodeRejects(t *testing.T) {
	for name, b := range map[string][]byte{
		"trailing":   append(cborText("x"), 0x00),
		"truncated":  {0x45, 1, 2}, // bytes(5) with 2 bytes
		"indefinite": {0x5f},
		"int key":    {0xa1, 0x01, 0x01}, // map{1:1}
	} {
		if _, err := cborDecode(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestVerifyAppAttestReasons(t *testing.T) {
	p := &attestationPayload{Provider: "APP_ATTEST", Status: "OK",
		KeyID: "k", Attestation: "!!!not-base64!!!"}

	v := verifyAppAttest(attestationConfig{}, p, "chal")
	if v.Verified || v.Reason != "verification not configured" {
		t.Fatalf("unconfigured: %+v", v)
	}

	cfg := attestationConfig{AppAttestAppID: "TEAM.com.app"}
	v = verifyAppAttest(cfg, p, "chal")
	if v.Verified || v.Reason != "attestation not base64" {
		t.Fatalf("bad base64: %+v", v)
	}

	p.Attestation = base64.StdEncoding.EncodeToString(cborText("nope"))
	v = verifyAppAttest(cfg, p, "chal")
	if v.Verified || v.Reason != "not an apple-appattest object" {
		t.Fatalf("wrong shape: %+v", v)
	}
	// Chain verification against Apple's real root is exercised only with a
	// genuine attestation blob; everything before it is covered above.
}

func TestExpectedNonceStable(t *testing.T) {
	a, b := expectedNonce("s1", "i1"), expectedNonce("s1", "i1")
	if a != b || a == "" || a == expectedNonce("s2", "i1") {
		t.Fatal("nonce not stable/distinct")
	}
	if len(a) != 43 { // 32 bytes base64url unpadded
		t.Fatalf("nonce length %d", len(a))
	}
}
