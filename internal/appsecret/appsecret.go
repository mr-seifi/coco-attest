package appsecret

import (
	"crypto/sha256"
	"os"
)

const demoPassphrase = "confidential-container-poc:application-key:v1"

func Default() []byte {
	p := os.Getenv("RELEASE_SECRET")
	if p == "" {
		p = demoPassphrase
	}
	k := sha256.Sum256([]byte(p))
	return k[:]
}
