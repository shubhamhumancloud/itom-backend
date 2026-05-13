package collector

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// CollectSoftware enumerates installed applications. Implementation per OS:
//   - Windows: `wmic product get` (slow but standard) — fallback to PowerShell
//     against the Uninstall registry keys.
//   - Linux:   `dpkg-query` (Debian/Ubuntu) or `rpm -qa` (RHEL/Fedora). First
//     one available wins.
//   - macOS:   `system_profiler SPApplicationsDataType -xml` would be ideal
//     but too slow; we walk /Applications directories and read Info.plist
//     versions for v1 (best-effort).
//
// Returns ErrUnsupportedOS on platforms we don't know how to enumerate.
// Designed to run at most once per 24 h — no perf budget pressure.
var ErrUnsupportedOS = errors.New("software inventory not implemented for this OS")

func CollectSoftware(ctx context.Context) ([]SoftwareItem, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	switch runtime.GOOS {
	case "linux":
		return collectLinuxSoftware(cctx)
	case "darwin":
		return collectMacSoftware(cctx)
	case "windows":
		return collectWindowsSoftware(cctx)
	default:
		return nil, ErrUnsupportedOS
	}
}

// ---------- Linux ----------

func collectLinuxSoftware(ctx context.Context) ([]SoftwareItem, error) {
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		return runDpkgQuery(ctx)
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		return runRPMQuery(ctx)
	}
	return nil, ErrUnsupportedOS
}

func runDpkgQuery(ctx context.Context) ([]SoftwareItem, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Maintainer}\t${Installed-Size}\n")
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var items []SoftwareItem
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || fields[0] == "" {
			continue
		}
		var sizeBytes uint64
		if len(fields) >= 4 {
			// dpkg installed-size is in kB.
			if kb := parseUint(fields[3]); kb > 0 {
				sizeBytes = kb * 1024
			}
		}
		item := SoftwareItem{
			Name:      fields[0],
			Version:   fields[1],
			Source:    "dpkg",
			SizeBytes: sizeBytes,
		}
		if len(fields) >= 3 {
			item.Publisher = fields[2]
		}
		items = append(items, item)
	}
	return items, nil
}

func runRPMQuery(ctx context.Context) ([]SoftwareItem, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa",
		"--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{SIZE}\n")
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var items []SoftwareItem
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || fields[0] == "" {
			continue
		}
		item := SoftwareItem{
			Name:    fields[0],
			Version: fields[1],
			Source:  "rpm",
		}
		if len(fields) >= 3 {
			item.Publisher = fields[2]
		}
		if len(fields) >= 4 {
			item.SizeBytes = parseUint(fields[3])
		}
		items = append(items, item)
	}
	return items, nil
}

// ---------- macOS ----------

func collectMacSoftware(ctx context.Context) ([]SoftwareItem, error) {
	// system_profiler is the canonical source. Use the JSON output for safety.
	cmd := exec.CommandContext(ctx, "system_profiler", "-json", "SPApplicationsDataType")
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	items, paths := parseMacAppJSON(raw)
	if sizes := macBundleSizes(ctx, paths); len(sizes) > 0 {
		for i, p := range paths {
			if sz, ok := sizes[p]; ok {
				items[i].SizeBytes = sz
			}
		}
	}
	return items, nil
}

// macBundleSizes shells out to `du -sk` with every app bundle path in one
// call. macOS `du -sk` prints "<KB>\t<path>" per line; we parse that into
// path→bytes. We deliberately use one batched invocation rather than 300+
// process spawns. Errors on individual paths (permissions, missing) are
// silently skipped — the size column just shows "—" for those rows.
func macBundleSizes(ctx context.Context, paths []string) map[string]uint64 {
	valid := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		valid = append(valid, p)
	}
	if len(valid) == 0 {
		return nil
	}
	args := append([]string{"-sk"}, valid...)
	out, _ := exec.CommandContext(ctx, "du", args...).Output()

	sizes := make(map[string]uint64, len(valid))
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// Format: "<kilobytes>\t<path>" (BSD du). Sometimes leading spaces.
		tab := strings.IndexByte(line, '\t')
		if tab <= 0 {
			continue
		}
		kb := parseUint(line[:tab])
		if kb == 0 {
			continue
		}
		sizes[line[tab+1:]] = kb * 1024
	}
	return sizes
}

// ---------- Windows ----------

func collectWindowsSoftware(ctx context.Context) ([]SoftwareItem, error) {
	// Read the Uninstall registry hives via PowerShell — much faster than
	// `wmic product` (which can take minutes) and covers the same apps.
	ps := `
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize |
  ConvertTo-Json -Compress
`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseWindowsAppJSON(raw), nil
}

func parseUint(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var n uint64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + uint64(ch-'0')
	}
	return n
}
