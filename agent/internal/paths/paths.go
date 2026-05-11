// Package paths centralises user-home-directory resolution.
//
// Why this exists:
//
//	Go's stdlib os.UserHomeDir() on Unix only reads $HOME. It does NOT
//	fall back to the OS user database (passwd / Open Directory). When
//	the agent is launched by launchd (macOS) or systemd (Linux) as a
//	system daemon, $HOME is usually unset — so every os.UserHomeDir()
//	call returns "$HOME is not defined" and our logger / buffer / config
//	initialisation crashes the process before anything useful happens.
//	launchd then retries, the daemon panics again, and after enough
//	failures launchd refuses further loads with the cryptic "Load
//	failed: 5: Input/output error".
//
//	UserHomeDir() here tries $HOME first (fast path, matches existing
//	behaviour for shell-launched runs), then falls back to user.Current(),
//	which consults the OS user database (getpwuid_r via cgo, or
//	/etc/passwd via pure Go).
package paths

import (
	"fmt"
	"os"
	"os/user"
)

// UserHomeDir returns the running user's home directory.
func UserHomeDir() (string, error) {
	if h := os.Getenv("HOME"); h != "" {
		return h, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	if u.HomeDir == "" {
		return "", fmt.Errorf("resolve home dir: user %q has no home directory", u.Username)
	}
	return u.HomeDir, nil
}
