package collector

import (
	"encoding/json"
	"strings"
)

// macOS system_profiler -json shape. We pull only the fields we surface so
// unknown keys don't break parsing across macOS versions.
type macAppEntry struct {
	Name         string   `json:"_name"`
	Version      string   `json:"version"`
	Path         string   `json:"path"`
	LastModified string   `json:"lastModified"`
	SignedBy     []string `json:"signed_by"`
	ObtainedFrom string   `json:"obtained_from"`
}
type macAppOutput struct {
	Apps []macAppEntry `json:"SPApplicationsDataType"`
}

// parseMacAppJSON returns SoftwareItems and a parallel slice of bundle paths
// so the caller can enrich SizeBytes via a separate `du` pass. Empty path
// strings mean system_profiler didn't report one for that entry.
func parseMacAppJSON(raw []byte) (items []SoftwareItem, paths []string) {
	var out macAppOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, nil
	}
	items = make([]SoftwareItem, 0, len(out.Apps))
	paths = make([]string, 0, len(out.Apps))
	for _, a := range out.Apps {
		if a.Name == "" {
			continue
		}
		items = append(items, SoftwareItem{
			Name:        a.Name,
			Version:     a.Version,
			Publisher:   macPublisherFromCert(a.SignedBy),
			InstalledAt: macInstalledFromTimestamp(a.LastModified),
			Source:      "mac_app",
		})
		paths = append(paths, a.Path)
	}
	return items, paths
}

// macPublisherFromCert turns the leaf signing certificate into a human-readable
// publisher. The cert chain order in system_profiler always has the leaf first.
//
//   - Apple-signed system apps     → "Apple"
//   - Developer ID signed apps     → "<Vendor Name>" (strips "Developer ID Application: " prefix and trailing "(TEAMID)")
//   - Mac App Store third-party    → "<Vendor Name>" (strips "3rd Party Mac Developer Application: " prefix)
//   - Anything else                → cert string verbatim
//   - Unsigned                     → ""
func macPublisherFromCert(signedBy []string) string {
	if len(signedBy) == 0 {
		return ""
	}
	s := signedBy[0]
	switch s {
	case "Software Signing", "Apple Mac OS Application Signing":
		return "Apple"
	}
	for _, prefix := range []string{
		"Developer ID Application: ",
		"3rd Party Mac Developer Application: ",
		"Apple Development: ",
	} {
		if strings.HasPrefix(s, prefix) {
			rest := s[len(prefix):]
			if idx := strings.LastIndex(rest, " ("); idx > 0 {
				return rest[:idx]
			}
			return rest
		}
	}
	return s
}

// macInstalledFromTimestamp turns an ISO timestamp like "2024-08-04T10:31:41Z"
// into a date string "2024-08-04". Returns "" on malformed input.
//
// Caveat: macOS's `lastModified` reflects when the bundle was last touched on
// disk, not necessarily when the user installed it. For preinstalled system
// apps this is the OS install / update date, which is the best signal
// available without an Installer Receipt scan (out of scope here).
func macInstalledFromTimestamp(ts string) string {
	if len(ts) < 10 {
		return ""
	}
	return ts[:10]
}

// Windows PowerShell ConvertTo-Json output. Single-item output is an object,
// multi-item output is an array — handle both.
type winAppEntry struct {
	DisplayName    string `json:"DisplayName"`
	DisplayVersion string `json:"DisplayVersion"`
	Publisher      string `json:"Publisher"`
	InstallDate    string `json:"InstallDate"` // YYYYMMDD
	EstimatedSize  uint64 `json:"EstimatedSize"`
}

func parseWindowsAppJSON(raw []byte) []SoftwareItem {
	if len(raw) == 0 {
		return nil
	}
	var entries []winAppEntry
	// Try array first.
	if err := json.Unmarshal(raw, &entries); err != nil {
		var single winAppEntry
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil
		}
		entries = []winAppEntry{single}
	}

	items := make([]SoftwareItem, 0, len(entries))
	for _, e := range entries {
		if e.DisplayName == "" {
			continue
		}
		var size uint64
		if e.EstimatedSize > 0 {
			size = e.EstimatedSize * 1024 // EstimatedSize is in KB.
		}
		items = append(items, SoftwareItem{
			Name:        e.DisplayName,
			Version:     e.DisplayVersion,
			Publisher:   e.Publisher,
			InstalledAt: parseWinDate(e.InstallDate),
			SizeBytes:   size,
			Source:      "msi",
		})
	}
	return items
}

func parseWinDate(s string) string {
	if len(s) != 8 {
		return ""
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return ""
		}
	}
	return s[:4] + "-" + s[4:6] + "-" + s[6:8]
}
