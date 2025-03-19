package keyrelease

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

func Wrap(pubDER, secret []byte) ([]byte, error) {
	pub, err := parseRSAPublic(pubDER)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, secret, []byte("kbs-key-release"))
}

func Unwrap(priv *rsa.PrivateKey, wrapped []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, []byte("kbs-key-release"))
}

func parseRSAPublic(der []byte) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	return pub, nil
}
