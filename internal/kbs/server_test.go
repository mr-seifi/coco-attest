package kbs_test

import (
	"net/http/httptest"
	"testing"

	"github.com/mr-seifi/coco-attest/internal/appsecret"
	"github.com/mr-seifi/coco-attest/internal/attest"
	"github.com/mr-seifi/coco-attest/internal/client"
	"github.com/mr-seifi/coco-attest/internal/kbs"
	"github.com/mr-seifi/coco-attest/internal/verify"
)

func newServer(t *testing.T, p verify.Policy) (*httptest.Server, []byte) {
	t.Helper()
	secret := appsecret.Default()
	ts := httptest.NewServer(kbs.New(verify.New(p), secret).Routes())
	t.Cleanup(ts.Close)
	return ts, secret
}

func TestAttestedKeyRelease(t *testing.T) {
	ts, secret := newServer(t, verify.DefaultPolicy())
	got, err := client.New(ts.URL).ReleaseKey()
	if err != nil {
		t.Fatalf("ReleaseKey: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("released secret does not match KBS secret")
	}
}

func TestUntrustedMeasurementRejected(t *testing.T) {

	p := verify.Policy{AllowedMeasurements: map[string]map[string]bool{
		attest.TEESampleSW: {"deadbeef": true},
	}}
	ts, _ := newServer(t, p)
	if _, err := client.New(ts.URL).ReleaseKey(); err == nil {
		t.Fatal("expected rejection for untrusted measurement, got none")
	}
}

func TestNonceSingleUse(t *testing.T) {
	ts, _ := newServer(t, verify.DefaultPolicy())
	c := client.New(ts.URL)
	if _, err := c.ReleaseKey(); err != nil {
		t.Fatalf("first release: %v", err)
	}

	if _, err := c.ReleaseKey(); err != nil {
		t.Fatalf("second release with fresh nonce: %v", err)
	}
}
