//go:build windows

package fingerprint

import (
	"github.com/yusufpapurcu/wmi"
)

func init() { hardwareIdentifiersFn = windowsHardwareIdentifiers }

type win32CSP struct{ UUID string }
type win32BIOS struct{ SerialNumber string }

func windowsHardwareIdentifiers() (uuid, serial string) {
	var csps []win32CSP
	if err := wmi.Query("SELECT UUID FROM Win32_ComputerSystemProduct", &csps); err == nil && len(csps) > 0 {
		uuid = csps[0].UUID
	}
	var bs []win32BIOS
	if err := wmi.Query("SELECT SerialNumber FROM Win32_BIOS", &bs); err == nil && len(bs) > 0 {
		serial = bs[0].SerialNumber
	}
	return uuid, serial
}
