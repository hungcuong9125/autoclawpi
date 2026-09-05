// Package config menyimpan konfigurasi runtime autoclawpi.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config adalah konfigurasi autoclawpi.
type Config struct {
	// Host untuk listen (default 127.0.0.1, jangan 0.0.0.0).
	Host string `json:"host"`
	// Port untuk listen (default 8787).
	Port int `json:"port"`
	// APIKey untuk melindungi server lokal ini. Kosong = tanpa auth.
	APIKey string `json:"api_key,omitempty"`
	// InferenceBase adalah base URL proxy AutoClaw.
	InferenceBase string `json:"inference_base,omitempty"`
	// UserAPIBase adalah base URL userapi (login/refresh).
	UserAPIBase string `json:"userapi_base,omitempty"`
	// RateLimitPerSec membatasi laju request inference (token/detik) utk hindari WAF.
	RateLimitPerSec float64 `json:"rate_limit_per_sec,omitempty"`
	// RateLimitBurst adalah kapasitas burst token bucket.
	RateLimitBurst int `json:"rate_limit_burst,omitempty"`
}

// Defaults mengisi nilai kosong dengan default yang aman.
func (c *Config) Defaults() {
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == 0 {
		c.Port = 8787
	}
	if c.InferenceBase == "" {
		c.InferenceBase = "https://autoglm-api.autoglm.ai/autoclaw-proxy/proxy/autoclaw"
	}
	if c.UserAPIBase == "" {
		c.UserAPIBase = "https://autoglm-api.autoglm.ai"
	}
}

// Dir mengembalikan direktori data autoclawpi.
func Dir() string {
	if d := os.Getenv("AUTOCLAWPI_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".autoclawpi"
	}
	return filepath.Join(home, ".autoclawpi")
}

// Path mengembalikan path file di dalam dir autoclawpi.
func Path(name string) string {
	return filepath.Join(Dir(), name)
}

// Load membaca config dari disk (jika ada), lalu menerapkan default.
func Load() (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(Path("config.json"))
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, err
		}
	}
	// Fallback env: API key boleh disuplai lewat environment ketika
	// config.json tidak menetapkan api_key (flag --api-key tetap
	// mengoverride keduanya).
	if c.APIKey == "" {
		c.APIKey = os.Getenv("AUTOCLAWPI_API_KEY")
	}
	c.Defaults()
	return c, nil
}

// Save menulis config ke disk.
func Save(c *Config) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(Path("config.json"), b, 0o600)
}
