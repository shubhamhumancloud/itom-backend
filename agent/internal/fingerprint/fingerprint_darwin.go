//go:build darwin

package fingerprint

import (
	"os/exec"
	"regexp"
)

func init() { hardwareIdentifiersFn = darwinHardwareIdentifiers }

// ioreg outputs lines like:
//
//	"IOPlatformUUID" = "ABCD1234-5678-..."
//	"IOPlatformSerialNumber" = "C02XX..."
//
// We grab both with one regex over the whole output.
var ioregFieldRe = regexp.MustCompile(`"([^"]+)"\s*=\s*"([^"]*)"`)

func darwinHardwareIdentifiers() (uuid, serial string) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").CombinedOutput()
	if err != nil {
		return "", ""
	}
	for _, m := range ioregFieldRe.FindAllSubmatch(out, -1) {
		switch string(m[1]) {
		case "IOPlatformUUID":
			uuid = string(m[2])
		case "IOPlatformSerialNumber":
			serial = string(m[2])
		}
	}
	return uuid, serial
}
