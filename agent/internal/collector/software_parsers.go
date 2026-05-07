package collector

import (
	"encoding/json"
)

// macOS system_profiler -json shape.
type macAppEntry struct {
	Name    string `json:"_name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}
type macAppOutput struct {
	Apps []macAppEntry `json:"SPApplicationsDataType"`
}

func parseMacAppJSON(raw []byte) []SoftwareItem {
	var out macAppOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	items := make([]SoftwareItem, 0, len(out.Apps))
	for _, a := range out.Apps {
		if a.Name == "" {
			continue
		}
		items = append(items, SoftwareItem{
			Name:    a.Name,
			Version: a.Version,
			Source:  "mac_app",
		})
	}
	return items
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
