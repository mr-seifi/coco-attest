package verify_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/mr-seifi/coco-attest/internal/attest"
	"github.com/mr-seifi/coco-attest/internal/verify"
)

func freshEvidence(t *testing.T, nonce []byte) *attest.Evidence {
	t.Helper()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	ev, err := attest.NewSampleAttester().GenerateEvidence(nonce, pub)
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	return ev
}

func TestValidEvidencePasses(t *testing.T) {
	v := verify.New(verify.DefaultPolicy())
	nonce := []byte("0123456789abcdef0123456789abcdef")
	ev := freshEvidence(t, nonce)
	if _, err := v.Appraise(ev, nonce); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	v := verify.New(verify.DefaultPolicy())
	nonce := []byte("0123456789abcdef0123456789abcdef")
	ev := freshEvidence(t, nonce)
	ev.Signature[0] ^= 0xff
	if _, err := v.Appraise(ev, nonce); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestWrongNonceRejected(t *testing.T) {
	v := verify.New(verify.DefaultPolicy())
	nonce := []byte("0123456789abcdef0123456789abcdef")
	ev := freshEvidence(t, nonce)
	if _, err := v.Appraise(ev, []byte("a-different-32-byte-nonce-value!")); err == nil {
		t.Fatal("stale/replayed nonce accepted")
	}
}

func TestSwappedPublicKeyRejected(t *testing.T) {
	v := verify.New(verify.DefaultPolicy())
	nonce := []byte("0123456789abcdef0123456789abcdef")
	ev := freshEvidence(t, nonce)

	otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ev.PublicKey, _ = x509.MarshalPKIXPublicKey(&otherPriv.PublicKey)
	if _, err := v.Appraise(ev, nonce); err == nil {
		t.Fatal("key substitution accepted: report_data binding not enforced")
	}
}
