package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/itom-mini/agent/internal/fingerprint"
	"github.com/itom-mini/agent/internal/paths"
)

type Config struct {
	ServerURL             string `json:"serverUrl"`
	AgentID               string `json:"agentId"`
	FingerprintHash       string `json:"fingerprintHash,omitempty"`
	LegacyFingerprintHash string `json:"legacyFingerprintHash,omitempty"`
	TenantID              string `json:"tenantId,omitempty"`
	IntervalSeconds       int    `json:"intervalSeconds"`
	FlushSeconds          int    `json:"flushSeconds"`
	HeartbeatSeconds      int    `json:"heartbeatSeconds"`
	MaxBatchSize          int    `json:"maxBatchSize"`
	MaxBufferRows         int    `json:"maxBufferRows"`
}

const (
	defaultServer        = "http://localhost:3005"
	defaultInterval      = 10
	defaultFlush         = 60
	defaultHeartbeat     = 30
	defaultMaxBatch      = 60
	defaultMaxBufferRows = 50000
	dirName              = ".itom-agent"
	fileName             = "config.json"
)

// Identity sourced from compile-time-baked values is the source of truth for
// tenantId and serverUrl. The values are seeded into ITOM_TENANT_ID and
// ITOM_SERVER_URL by main() before Load is called, so the existing env-var
// path picks them up on first boot. On subsequent boots the patched binary
// always overrides whatever happens to be in config.json — this prevents
// stale config from outlasting a re-install with new tenant/server values.

func defaultPath() (string, error) {
	home, err := paths.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, dirName, fileName), nil
}

// Load reads config from path (or default location).
//
// Identity rule: AgentID is derived deterministically from
// (tenantId, OS machine-id, sorted physical MAC addresses) via UUIDv5.
// On first run we compute and persist it. On subsequent runs we trust
// what is on disk — even if the fingerprint drifts (e.g. NIC swap), the
// backend is told the current FingerprintHash and DisplayName so it can
// reconcile if needed. Only when AgentID is missing do we recompute.
func Load(path string) (*Config, error) {
	if path == "" {
		p, err := defaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}

	ctx := context.Background()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		tenantID := os.Getenv("ITOM_TENANT_ID")
		fp, err := fingerprint.Compute(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: %w", err)
		}
		cfg := &Config{
			ServerURL:             envOr("ITOM_SERVER_URL", defaultServer),
			AgentID:               fp.AgentID,
			FingerprintHash:       fp.Hash,
			LegacyFingerprintHash: fp.LegacyHash,
			TenantID:              tenantID,
			IntervalSeconds:       envOrInt("ITOM_INTERVAL_SECONDS", defaultInterval),
			FlushSeconds:          defaultFlush,
			HeartbeatSeconds:      defaultHeartbeat,
			MaxBatchSize:          defaultMaxBatch,
			MaxBufferRows:         defaultMaxBufferRows,
		}
		if err := save(path, cfg); err != nil {
			return nil, fmt.Errorf("create config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "created new config at %s (agentId=%s)\n",
			path, cfg.AgentID)
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
	if v := os.Getenv("ITOM_TENANT_ID"); v != "" && v != cfg.TenantID {
		cfg.TenantID = v
		dirty = true
	}

	// If AgentID is missing (legacy config or user wiped it), regenerate
	// deterministically from the current fingerprint. Otherwise we KEEP the
	// existing AgentID — never recompute it on upgrade — and only refresh
	// the hashes so the backend can reconcile.
	if cfg.AgentID == "" {
		fp, err := fingerprint.Compute(ctx, cfg.TenantID)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: %w", err)
		}
		cfg.AgentID = fp.AgentID
		cfg.FingerprintHash = fp.Hash
		cfg.LegacyFingerprintHash = fp.LegacyHash
		dirty = true
	} else {
		fp, err := fingerprint.Compute(ctx, cfg.TenantID)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: %w", err)
		}
		if cfg.FingerprintHash != fp.Hash {
			cfg.FingerprintHash = fp.Hash
			dirty = true
		}
		if cfg.LegacyFingerprintHash != fp.LegacyHash {
			cfg.LegacyFingerprintHash = fp.LegacyHash
			dirty = true
		}
	}

	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = defaultInterval
		dirty = true
	}
	if v := os.Getenv("ITOM_SERVER_URL"); v != "" && v != cfg.ServerURL {
		cfg.ServerURL = v
		dirty = true
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = defaultServer
		dirty = true
	}
	if v := envOrInt("ITOM_INTERVAL_SECONDS", 0); v > 0 && v != cfg.IntervalSeconds {
		cfg.IntervalSeconds = v
		dirty = true
	}
	if cfg.FlushSeconds <= 0 {
		cfg.FlushSeconds = defaultFlush
		dirty = true
	}
	if cfg.HeartbeatSeconds <= 0 {
		cfg.HeartbeatSeconds = defaultHeartbeat
		dirty = true
	}
	if cfg.MaxBatchSize <= 0 {
		cfg.MaxBatchSize = defaultMaxBatch
		dirty = true
	}
	if cfg.MaxBufferRows <= 0 {
		cfg.MaxBufferRows = defaultMaxBufferRows
		dirty = true
	}
	if dirty {
		if err := save(path, &cfg); err != nil {
			return nil, fmt.Errorf("persist config: %w", err)
		}
	}
	return &cfg, nil
}

// Save persists the given config to disk at path (or the default location).
// Used by callers that mutate the config at runtime — for example, when the
// backend reassigns the AgentID during register and the agent must adopt it.
func Save(path string, cfg *Config) error {
	if path == "" {
		p, err := defaultPath()
		if err != nil {
			return err
		}
		path = p
	}
	return save(path, cfg)
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
