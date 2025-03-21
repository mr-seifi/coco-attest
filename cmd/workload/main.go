package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/mr-seifi/coco-attest/internal/client"
	"github.com/mr-seifi/coco-attest/internal/seal"
)

type app struct {
	mu     sync.RWMutex
	config []byte
	key    []byte
	ready  bool
}

func main() {
	addr := envOr("WORKLOAD_ADDR", ":9090")
	kbsURL := envOr("KBS_URL", "http://127.0.0.1:8080")
	sealedPath := envOr("SEALED_CONFIG", "config.sealed.bin")

	a := &app{}

	t0 := time.Now()
	key, err := attestWithRetry(kbsURL, 20, 250*time.Millisecond)
	if err != nil {
		log.Fatalf("attestation/key release failed, refusing to serve: %v", err)
	}
	log.Printf("key released via attestation in %s", time.Since(t0).Round(time.Millisecond))

	sealed, err := os.ReadFile(sealedPath)
	if err != nil {
		log.Fatalf("read sealed config %s: %v", sealedPath, err)
	}
	config, err := seal.Open(key, sealed)
	if err != nil {
		log.Fatalf("unseal config (wrong key?): %v", err)
	}
	a.mu.Lock()
	a.key, a.config, a.ready = key, config, true
	a.mu.Unlock()
	log.Printf("config unsealed (%d bytes); workload ready", len(config))

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.health)
	mux.HandleFunc("/config", a.serveConfig)
	mux.HandleFunc("/sign", a.sign)

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("workload listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("workload: %v", err)
	}
}

func attestWithRetry(kbsURL string, attempts int, delay time.Duration) ([]byte, error) {
	c := client.New(kbsURL)
	var last error
	for i := 0; i < attempts; i++ {
		key, err := c.ReleaseKey()
		if err == nil {
			return key, nil
		}
		last = err
		time.Sleep(delay)
	}
	return nil, last
}

func (a *app) health(w http.ResponseWriter, _ *http.Request) {
	a.mu.RLock()
	ready := a.ready
	a.mu.RUnlock()
	if !ready {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok\n"))
}

func (a *app) serveConfig(w http.ResponseWriter, _ *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain")
	w.Write(a.config)
}

func (a *app) sign(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	key := a.key
	a.mu.RUnlock()
	msg := r.URL.Query().Get("msg")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	w.Write([]byte(hex.EncodeToString(mac.Sum(nil)) + "\n"))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
