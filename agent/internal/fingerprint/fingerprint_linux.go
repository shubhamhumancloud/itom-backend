//go:build linux

package fingerprint

import (
	"os"
	"strings"
)

func init() { hardwareIdentifiersFn = linuxHardwareIdentifiers }

func linuxHardwareIdentifiers() (uuid, serial string) {
	uuid = readTrim("/sys/class/dmi/id/product_uuid")
	serial = readTrim("/sys/class/dmi/id/product_serial")
	// Containers and VMs without DMI passthrough leave product_uuid empty —
	// /etc/machine-id is the next-best stable identifier.
	if uuid == "" {
		uuid = readTrim("/etc/machine-id")
	}
	return uuid, serial
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
