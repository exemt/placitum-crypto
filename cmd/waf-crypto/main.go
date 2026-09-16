package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-crypto/internal/config"
	"github.com/exemt/placitum-crypto/internal/contourkey"
	"github.com/exemt/placitum-crypto/internal/httpapi"
	"github.com/exemt/placitum-shared/logkit"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	journal := logkit.Open(logkit.Options{Service: "crypto", Level: cfg.LogLevel})
	defer journal.Close()

	log := journal.Log

	log.Info("build", "version", version, "revision", revision)
	slog.SetDefault(log)

	var key *contourkey.Key
	if cfg.NodeKey == "" {
		log.Warn("WAF_NODE_KEY is empty, /v1/certificates/metadata will answer 503 until it is set")
	} else {
		key, err = contourkey.Load(cfg.NodeKey)
		if err != nil {
			return fmt.Errorf("contour key: %w", err)
		}
		log.Info("contour key loaded", "fingerprint", key.Fingerprint)
	}

	deps := httpapi.Deps{
		Key:           key,
		ControllerURL: cfg.ControllerURL,
		Client:        &http.Client{Timeout: cfg.RequestTimeout},
		Log:           log,
	}

	srv := &http.Server{
		Addr:              cfg.HTTP,
		Handler:           httpapi.Handler(deps),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.NatsURL != "" {
		nc, err := nats.Connect(cfg.NatsURL,
			nats.Name("waf-crypto"),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(500*time.Millisecond),
			nats.RetryOnFailedConnect(true),
		)
		if err != nil {
			log.Warn("log bus", "url", cfg.NatsURL, "error", err.Error())
		} else {
			defer nc.Close()

			journal.Attach(ctx, nc)
			defer journal.Close()
		}
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("http listen", "addr", cfg.HTTP)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errc <- fmt.Errorf("http: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("draining")
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		return nil
	case err := <-errc:
		return err
	}
}
