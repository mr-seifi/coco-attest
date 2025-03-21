package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mr-seifi/coco-attest/internal/appsecret"
	"github.com/mr-seifi/coco-attest/internal/kbs"
	"github.com/mr-seifi/coco-attest/internal/verify"
)

func main() {
	addr := envOr("KBS_ADDR", ":8080")

	srv := kbs.New(verify.New(verify.DefaultPolicy()), appsecret.Default())
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("KBS listening on %s (%s)", addr, srv)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("kbs: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	log.Printf("KBS stopped")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
