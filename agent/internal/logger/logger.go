package logger

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// Logger is a thin alias so callers can `log.Info(...)` directly.
type Logger = slog.Logger

// New writes plain-text logs to both stderr and ~/.itom-agent/agent.log.
// File rotation is intentionally omitted in Phase 1 — add lumberjack in Phase 3.
func New() (*Logger, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".itom-agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, "agent.log")
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	multi := io.MultiWriter(file, os.Stderr)
	handler := slog.NewTextHandler(multi, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(handler), nil
}
