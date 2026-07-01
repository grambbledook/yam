package config

import (
	"os"

	"github.com/spf13/pflag"
)

type Config struct {
	Port      string
	IssuerURL string
	KeyPath   string
}

func Load() Config {
	port := pflag.String("port", envOr("PORT", "8080"), "Server port")
	issuerURL := pflag.String("issuer-url", envOr("ISSUER_URL", "http://localhost:8080"), "Issuer URL")
	keyPath := pflag.String("key-path", envOr("KEY_PATH", ""), "Path to key file")

	pflag.Parse()

	return Config{
		Port:      *port,
		IssuerURL: *issuerURL,
		KeyPath:   *keyPath,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
