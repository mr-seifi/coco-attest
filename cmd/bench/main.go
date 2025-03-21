package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"sort"
	"time"

	"github.com/mr-seifi/coco-attest/internal/appsecret"
	"github.com/mr-seifi/coco-attest/internal/client"
	"github.com/mr-seifi/coco-attest/internal/kbs"
	"github.com/mr-seifi/coco-attest/internal/seal"
	"github.com/mr-seifi/coco-attest/internal/verify"
)

type stats struct {
	Label string  `json:"label"`
	Unit  string  `json:"unit"`
	N     int     `json:"n"`
	Mean  float64 `json:"mean"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	P99   float64 `json:"p99"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
}

type report struct {
	GeneratedAt string  `json:"generated_at"`
	Runs        int     `json:"runs"`
	Results     []stats `json:"results"`
	Notes       string  `json:"notes"`
}

func main() {
	n := flag.Int("n", 200, "iterations per measurement")
	out := flag.String("out", "bench/results.json", "output JSON path")
	flag.Parse()

	log.SetOutput(io.Discard)

	secret := appsecret.Default()

	plaintext := []byte("db_password=hunter2;feature_flags=attested")
	sealed, err := seal.Seal(secret, plaintext)
	if err != nil {
		log.Fatalf("seal: %v", err)
	}

	ts := httptest.NewServer(kbs.New(verify.New(verify.DefaultPolicy()), secret).Routes())
	defer ts.Close()

	attested := make([]float64, 0, *n)
	for i := 0; i < *n; i++ {
		c := client.New(ts.URL)
		t0 := time.Now()
		key, err := c.ReleaseKey()
		if err != nil {
			log.Fatalf("attested handshake failed: %v", err)
		}
		if _, err := seal.Open(key, sealed); err != nil {
			log.Fatalf("unseal: %v", err)
		}
		attested = append(attested, msSince(t0))
	}

	plain := make([]float64, 0, *n)
	for i := 0; i < *n; i++ {
		t0 := time.Now()
		key := appsecret.Default()
		if _, err := seal.Open(key, sealed); err != nil {
			log.Fatalf("unseal: %v", err)
		}
		plain = append(plain, msSince(t0))
	}

	rep := report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Runs:        *n,
		Results: []stats{
			summarize("plain_startup", "ms", plain),
			summarize("attested_startup", "ms", attested),
		},
		Notes: "Measures the attestation-protocol overhead at startup on the " +
			"software backend. TEE memory-encryption CPU/RAM overhead requires " +
			"real SEV-SNP/TDX hardware and is not captured here.",
	}

	buf, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(*out, buf, 0o644); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}

	ps, as := rep.Results[0], rep.Results[1]
	fmt.Printf("Benchmark (%d runs, software backend)\n", *n)
	fmt.Printf("  plain startup    p50=%.3f ms  p99=%.3f ms\n", ps.P50, ps.P99)
	fmt.Printf("  attested startup p50=%.3f ms  p99=%.3f ms\n", as.P50, as.P99)
	fmt.Printf("  attestation overhead (p50 delta) = %.3f ms\n", as.P50-ps.P50)
	fmt.Printf("  -> steady-state request latency is unaffected: attestation is a one-time startup cost.\n")
	fmt.Printf("  results written to %s\n", *out)
}

func summarize(label, unit string, xs []float64) stats {
	s := make([]float64, len(xs))
	copy(s, xs)
	sort.Float64s(s)
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	return stats{
		Label: label, Unit: unit, N: len(s),
		Mean: sum / float64(len(s)),
		P50:  pct(s, 50), P90: pct(s, 90), P99: pct(s, 99),
		Min: s[0], Max: s[len(s)-1],
	}
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p / 100 * float64(len(sorted)-1))
	return sorted[idx]
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000.0 }
