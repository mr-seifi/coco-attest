package attest

import "crypto/sha256"

const (
	TEESampleSW = "sample-sw"
	TEESevSNP   = "sev-snp"
	TEETDX      = "tdx"
)

type Evidence struct {
	TEEType     string `json:"tee_type"`
	Nonce       string `json:"nonce"`
	Measurement string `json:"measurement"`
	ReportData  string `json:"report_data"`
	PublicKey   []byte `json:"public_key"`
	Signature   []byte `json:"signature"`
}

func ReportData(nonce, publicKey []byte) [32]byte {
	h := sha256.New()
	h.Write(nonce)
	h.Write(publicKey)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type Attester interface {
	Type() string
	GenerateEvidence(nonce, publicKey []byte) (*Evidence, error)
}

func Detect() Attester {
	if a := detectHardware(); a != nil {
		return a
	}
	return NewSampleAttester()
}
