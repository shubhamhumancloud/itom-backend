// Package fingerprint derives a stable identity for the host the agent runs on.
//
// Inputs combined: tenantId | hardwareUUID | hardwareSerial.
// Output: a deterministic UUIDv5 (the AgentID) and a sha256 hash of the inputs
// (FingerprintHash, used by the backend as a reconciliation key).
//
// Rationale for dropping MAC addresses (the previous formula): MAC randomisation
// (Wi-Fi privacy in 2026), USB-C dongles, virtualisation, and Apple Silicon NIC
// suspend all make MACs unstable across boots. Hardware UUID + hardware serial
// are read from firmware-level tables that don't change unless someone replaces
// the motherboard or reinstalls the OS.
//
// Per-OS sources (defined in fingerprint_<os>.go):
//
//	macOS:   IOPlatformUUID + IOPlatformSerialNumber via `ioreg`.
//	Linux:   /sys/class/dmi/id/product_uuid + /sys/class/dmi/id/product_serial,
//	         falling back to /etc/machine-id when DMI isn't readable.
//	Windows: Win32_ComputerSystemProduct.UUID + Win32_BIOS.SerialNumber via WMI.
//
// Backwards compatibility: existing agents already have AgentIDs persisted in
// config.json — those are read on boot and never recomputed. Only fresh
// installs hit this code. To smooth in-place upgrades on the backend, Result
// also carries LegacyHash (the old tenantId|machineId|macs hash) so the
// register endpoint can match the upgrading device against its existing row
// for one release; remove LegacyHash after the next release.
package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/host"
)

// Fixed namespace UUID for ITOM agent IDs. Do not change — every existing
// deterministic ID is derived from this namespace.
var namespace = uuid.MustParse("8a3f5e2d-9c4b-4a1f-b2d8-7e1f3c6a9b5d")

// hardwareIdentifiersFn is the seam that OS-specific files populate in init().
// Tests override it to assert determinism without touching real hardware.
var hardwareIdentifiersFn = func() (string, string) { return "", "" }

type Result struct {
	AgentID        string // deterministic UUIDv5 from the new formula
	Hash           string // sha256 hex of: tenantId|hwUUID|hwSerial
	LegacyHash     string // sha256 hex of: tenantId|machineId|macs (transition aid)
	HardwareUUID   string
	HardwareSerial string
}

// Compute resolves the host's hardware identity and returns a deterministic
// AgentID. Returns an error when both hwUUID and hwSerial are empty so the
// agent refuses to start with a useless fingerprint.
func Compute(ctx context.Context, tenantID string) (Result, error) {
	hwUUID, hwSerial := hardwareIdentifiersFn()
	hwUUID = strings.ToLower(strings.TrimSpace(hwUUID))
	hwSerial = strings.ToLower(strings.TrimSpace(hwSerial))

	if hwUUID == "" && hwSerial == "" {
		return Result{}, errors.New(
			"could not read hardware UUID or serial number — refusing to start " +
				"the agent with an empty fingerprint")
	}
	if hwUUID == "" {
		slog.Warn("fingerprint: hardware UUID empty, falling back to serial only")
	}

	raw := joinFingerprintInputs(tenantID, hwUUID, hwSerial)
	id, hash := deriveID(raw)
	legacy := legacyHashOf(ctx, tenantID)

	slog.Debug("fingerprint computed",
		"hardwareUUID", hwUUID,
		"hardwareSerial", hwSerial,
		"agentID", id)

	return Result{
		AgentID:        id,
		Hash:           hash,
		LegacyHash:     legacy,
		HardwareUUID:   hwUUID,
		HardwareSerial: hwSerial,
	}, nil
}

// joinFingerprintInputs is split out (and tested) so the byte sequence sent
// through uuid.NewSHA1 stays stable across runs.
func joinFingerprintInputs(tenantID, hwUUID, hwSerial string) string {
	return strings.Join([]string{
		strings.TrimSpace(tenantID),
		strings.ToLower(strings.TrimSpace(hwUUID)),
		strings.ToLower(strings.TrimSpace(hwSerial)),
	}, "|")
}

func deriveID(raw string) (id, hashHex string) {
	sum := sha256.Sum256([]byte(raw))
	return uuid.NewSHA1(namespace, []byte(raw)).String(), hex.EncodeToString(sum[:])
}

// legacyHashOf reproduces the previous (MAC-based) formula solely so the
// backend can reconcile devices that upgrade in place. Drop this and the
// LegacyHash field two releases after this one ships.
func legacyHashOf(ctx context.Context, tenantID string) string {
	machineID, _ := host.HostIDWithContext(ctx)
	machineID = strings.ToLower(strings.TrimSpace(machineID))
	raw := strings.Join([]string{
		strings.TrimSpace(tenantID),
		machineID,
		strings.Join(physicalMACs(), ","),
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// physicalMACs returns lowercased MACs from likely-physical interfaces, sorted.
// Only used by legacyHashOf — the new formula no longer touches MACs.
func physicalMACs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac := strings.ToLower(iface.HardwareAddr.String())
		if mac == "" {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue
		}
		if seen[mac] {
			continue
		}
		seen[mac] = true
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return macs
}

var virtualInterfaceTokens = []string{
	"docker", "veth", "vethernet", "vmnet", "vbox", "virbr",
	"br-", "tun", "tap", "ppp", "hyper-v", "wsl",
	"loopback", "bluetooth", "teredo", "isatap", "npcap",
}

func isVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, t := range virtualInterfaceTokens {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}
