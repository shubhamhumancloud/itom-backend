package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type Config struct {
	ServerURL       string `json:"serverUrl"`
	AgentID         string `json:"agentId"`
	IntervalSeconds int    `json:"intervalSeconds"`
}

const (
	defaultServer   = "http://localhost:3000"
	defaultInterval = 10
	dirName         = ".itom-agent"
	fileName        = "config.json"
)

func defaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, dirName, fileName), nil
}

// Load reads config from path (or default location). On first run it creates
// a config file with a generated agentId. Env vars override the defaults
// for first-run creation only:
//
//	ITOM_SERVER_URL — sets serverUrl
//	ITOM_INTERVAL_SECONDS — sets intervalSeconds
func Load(path string) (*Config, error) {
	if path == "" {
		p, err := defaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := &Config{
			ServerURL:       envOr("ITOM_SERVER_URL", defaultServer),
			AgentID:         uuid.NewString(),
			IntervalSeconds: envOrInt("ITOM_INTERVAL_SECONDS", defaultInterval),
		}
		if err := save(path, cfg); err != nil {
			return nil, fmt.Errorf("create config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "created new config at %s\n", path)
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	dirty := false
	if cfg.AgentID == "" {
		cfg.AgentID = uuid.NewString()
		dirty = true
	}
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = defaultInterval
		dirty = true
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = defaultServer
		dirty = true
	}
	if dirty {
		if err := save(path, &cfg); err != nil {
			return nil, fmt.Errorf("persist config: %w", err)
		}
	}
	return &cfg, nil
}

func save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 {
		return fallback
	}
	return n
}
