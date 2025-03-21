package main

import (
	"flag"
	"log"
	"os"

	"github.com/mr-seifi/coco-attest/internal/appsecret"
	"github.com/mr-seifi/coco-attest/internal/seal"
)

func main() {
	in := flag.String("in", "config.plain.txt", "plaintext config to seal")
	out := flag.String("out", "config.sealed.bin", "output sealed file")
	flag.Parse()

	plain, err := os.ReadFile(*in)
	if err != nil {
		log.Fatalf("read %s: %v", *in, err)
	}
	blob, err := seal.Seal(appsecret.Default(), plain)
	if err != nil {
		log.Fatalf("seal: %v", err)
	}
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	log.Printf("sealed %d bytes -> %s (%d bytes)", len(plain), *out, len(blob))
}
