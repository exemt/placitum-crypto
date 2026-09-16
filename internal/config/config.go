package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/exemt/placitum-shared/loglevel"
)

type Config struct {
	HTTP           string
	NodeKey        string
	ControllerURL  string
	RequestTimeout time.Duration
	LogLevel       slog.Level
	NatsURL        string
}

func Load() (*Config, error) {
	c := &Config{
		HTTP:          envKeep("WAF_CRYPTO_HTTP", ":8093"),
		NodeKey:       env("WAF_NODE_KEY", ""),
		ControllerURL: strings.TrimRight(env("WAF_CONTROLLER_URL", ""), "/"),
		NatsURL:       env("WAF_NATS_URL", ""),
	}

	var err error

	if c.LogLevel, err = parseLevel(env("WAF_CRYPTO_LOG", "info")); err != nil {
		return nil, err
	}

	if c.RequestTimeout, err = envDuration("WAF_CRYPTO_REQUEST_TIMEOUT", 5*time.Second); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if c.HTTP == "" {
		return fmt.Errorf("WAF_CRYPTO_HTTP is empty")
	}

	if c.ControllerURL == "" {
		return fmt.Errorf("WAF_CONTROLLER_URL is empty")
	}

	return nil
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}

func envKeep(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}

	return def
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return d, nil
}

func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_CRYPTO_LOG: %w", err)
	}

	return level, nil
}
