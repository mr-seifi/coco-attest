package kbs

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/mr-seifi/coco-attest/internal/attest"
	"github.com/mr-seifi/coco-attest/internal/keyrelease"
	"github.com/mr-seifi/coco-attest/internal/verify"
)

const nonceTTL = 2 * time.Minute

type Server struct {
	verifier *verify.Verifier
	secret   []byte

	mu     sync.Mutex
	nonces map[string]time.Time
}

func New(v *verify.Verifier, secret []byte) *Server {
	return &Server{
		verifier: v,
		secret:   secret,
		nonces:   make(map[string]time.Time),
	}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/challenge", s.handleChallenge)
	mux.HandleFunc("/attest", s.handleAttest)
	return mux
}

type challengeResp struct {
	Nonce string `json:"nonce"`
}

type attestResp struct {
	WrappedKey  string `json:"wrapped_key"`
	Measurement string `json:"measurement"`
	TEEType     string `json:"tee_type"`
}

type errResp struct {
	Error string `json:"error"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		writeErr(w, http.StatusInternalServerError, "nonce generation failed")
		return
	}
	enc := b64(nonce)
	s.mu.Lock()
	s.gcLocked()
	s.nonces[enc] = time.Now()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, challengeResp{Nonce: enc})
}

func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var e attest.Evidence
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&e); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid evidence: "+err.Error())
		return
	}

	if !s.consumeNonce(e.Nonce) {
		writeErr(w, http.StatusUnauthorized, "unknown, expired, or already-used nonce")
		return
	}
	rawNonce, err := unb64(e.Nonce)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "malformed nonce")
		return
	}

	result, err := s.verifier.Appraise(&e, rawNonce)
	if err != nil {

		log.Printf("attestation rejected: %v", err)
		writeErr(w, http.StatusForbidden, "attestation failed: "+err.Error())
		return
	}

	wrapped, err := keyrelease.Wrap(e.PublicKey, s.secret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key wrap failed")
		return
	}

	log.Printf("key released: tee=%s measurement=%s", result.TEEType, result.Measurement)
	writeJSON(w, http.StatusOK, attestResp{
		WrappedKey:  b64(wrapped),
		Measurement: result.Measurement,
		TEEType:     result.TEEType,
	})
}

func (s *Server) consumeNonce(enc string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	issued, ok := s.nonces[enc]
	if !ok {
		return false
	}
	delete(s.nonces, enc)
	return time.Since(issued) <= nonceTTL
}

func (s *Server) gcLocked() {
	cutoff := time.Now().Add(-nonceTTL)
	for n, t := range s.nonces {
		if t.Before(cutoff) {
			delete(s.nonces, n)
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, errResp{Error: msg})
}

func (s *Server) String() string { return fmt.Sprintf("kbs(secret=%d bytes)", len(s.secret)) }
