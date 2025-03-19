package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

const sampleDeviceSeed = "confidential-container-poc:sample-device-key:v1:DO-NOT-USE-IN-PROD"

func SampleDevicePrivateKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(sampleDeviceSeed))
	return ed25519.NewKeyFromSeed(seed[:])
}

func SampleDevicePublicKey() ed25519.PublicKey {
	return SampleDevicePrivateKey().Public().(ed25519.PublicKey)
}

func SampleMeasurement() string {
	digest := os.Getenv("WORKLOAD_LAUNCH_DIGEST")
	if digest == "" {
		digest = "workload:greeter:v1"
	}
	m := sha256.Sum256([]byte("launch-digest:" + digest))
	return hex.EncodeToString(m[:])
}

type sampleAttester struct {
	priv ed25519.PrivateKey
}

func NewSampleAttester() Attester {
	return &sampleAttester{priv: SampleDevicePrivateKey()}
}

func (a *sampleAttester) Type() string { return TEESampleSW }

func (a *sampleAttester) GenerateEvidence(nonce, publicKey []byte) (*Evidence, error) {
	if len(nonce) == 0 {
		return nil, fmt.Errorf("attest: empty nonce")
	}
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("attest: empty public key")
	}
	rd := ReportData(nonce, publicKey)
	e := &Evidence{
		TEEType:     TEESampleSW,
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		Measurement: SampleMeasurement(),
		ReportData:  hex.EncodeToString(rd[:]),
		PublicKey:   publicKey,
	}
	e.Signature = ed25519.Sign(a.priv, CanonicalReport(e))
	return e, nil
}
