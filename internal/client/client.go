package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mr-seifi/coco-attest/internal/attest"
	"github.com/mr-seifi/coco-attest/internal/keyrelease"
)

type Client struct {
	BaseURL  string
	Attester attest.Attester
	HTTP     *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL:  baseURL,
		Attester: attest.Detect(),
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) ReleaseKey() ([]byte, error) {

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal pubkey: %w", err)
	}

	nonce, err := c.challenge()
	if err != nil {
		return nil, err
	}

	ev, err := c.Attester.GenerateEvidence(nonce, pubDER)
	if err != nil {
		return nil, fmt.Errorf("generate evidence: %w", err)
	}

	wrapped, err := c.attest(ev)
	if err != nil {
		return nil, err
	}

	secret, err := keyrelease.Unwrap(priv, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}
	return secret, nil
}

func (c *Client) challenge() ([]byte, error) {
	resp, err := c.HTTP.Post(c.BaseURL+"/challenge", "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("challenge: %s", body(resp))
	}
	var cr struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("challenge decode: %w", err)
	}
	return base64.StdEncoding.DecodeString(cr.Nonce)
}

func (c *Client) attest(ev *attest.Evidence) ([]byte, error) {
	buf, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Post(c.BaseURL+"/attest", "application/json", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attest rejected (%d): %s", resp.StatusCode, body(resp))
	}
	var ar struct {
		WrappedKey string `json:"wrapped_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, fmt.Errorf("attest decode: %w", err)
	}
	return base64.StdEncoding.DecodeString(ar.WrappedKey)
}

func body(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return string(bytes.TrimSpace(b))
}
