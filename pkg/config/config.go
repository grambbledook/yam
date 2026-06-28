package config

import "os"

type Config struct {
	Port      string
	IssuerURL string
	KeyPath   string
}

func DefaultConfig() Config {
	return Config{
		Port:      getenv("PORT", "8080"),
		IssuerURL: getenv("ISSUER_URL", "http://localhost:8080"),
		KeyPath:   getenv("KEY_PATH", ""),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
