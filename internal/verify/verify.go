package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/mr-seifi/coco-attest/internal/attest"
)

type Policy struct {
	AllowedMeasurements map[string]map[string]bool
}

func DefaultPolicy() Policy {
	return Policy{
		AllowedMeasurements: map[string]map[string]bool{
			attest.TEESampleSW: {attest.SampleMeasurement(): true},
		},
	}
}

type Verifier struct {
	trustAnchors map[string]ed25519.PublicKey
	policy       Policy
}

func New(policy Policy) *Verifier {
	return &Verifier{
		trustAnchors: map[string]ed25519.PublicKey{
			attest.TEESampleSW: attest.SampleDevicePublicKey(),
		},
		policy: policy,
	}
}

type Result struct {
	TEEType     string
	Measurement string
}

func (v *Verifier) Appraise(e *attest.Evidence, expectedNonce []byte) (*Result, error) {
	anchor, ok := v.trustAnchors[e.TEEType]
	if !ok {
		return nil, fmt.Errorf("unknown or unsupported TEE type %q", e.TEEType)
	}

	if !ed25519.Verify(anchor, attest.CanonicalReport(e), e.Signature) {
		return nil, fmt.Errorf("report signature is not valid for TEE type %q", e.TEEType)
	}

	gotNonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return nil, fmt.Errorf("malformed nonce: %w", err)
	}
	if subtle.ConstantTimeCompare(gotNonce, expectedNonce) != 1 {
		return nil, fmt.Errorf("nonce mismatch: report is stale or replayed")
	}

	wantRD := attest.ReportData(expectedNonce, e.PublicKey)
	gotRD, err := hex.DecodeString(e.ReportData)
	if err != nil {
		return nil, fmt.Errorf("malformed report_data: %w", err)
	}
	if subtle.ConstantTimeCompare(gotRD, wantRD[:]) != 1 {
		return nil, fmt.Errorf("report_data does not bind the presented public key")
	}

	if sha256.Sum256(e.PublicKey) == [32]byte{} {
		return nil, fmt.Errorf("empty public key")
	}

	allowed := v.policy.AllowedMeasurements[e.TEEType]
	if len(allowed) > 0 && !allowed[e.Measurement] {
		return nil, fmt.Errorf("measurement %s is not in the trusted allowlist", e.Measurement)
	}

	return &Result{TEEType: e.TEEType, Measurement: e.Measurement}, nil
}
