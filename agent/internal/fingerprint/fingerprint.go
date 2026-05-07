// Package fingerprint derives a stable identity for the host the agent runs on.
//
// Inputs combined: tenantId | OS machine-id | sorted physical MAC addresses.
// Output: a deterministic UUIDv5 (the AgentID) and a sha256 hash of the inputs
// (FingerprintHash, used by the backend as a reconciliation key).
//
// Same machine + same tenant produces the same AgentID forever. Reinstalling
// the agent or wiping the config file does not change it. Reinstalling the OS
// or replacing the motherboard will, because those events change the machine-id.
package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/host"
)

// Fixed namespace UUID for ITOM agent IDs. Do not change this — every existing
// agent's deterministic ID is derived from this namespace.
var namespace = uuid.MustParse("8a3f5e2d-9c4b-4a1f-b2d8-7e1f3c6a9b5d")

type Result struct {
	AgentID   string // deterministic UUIDv5
	Hash      string // sha256 hex of the raw fingerprint inputs
	MachineID string
	MACs      []string
}

func Compute(ctx context.Context, tenantID string) Result {
	machineID, _ := host.HostIDWithContext(ctx)
	machineID = strings.ToLower(strings.TrimSpace(machineID))

	macs := physicalMACs()

	raw := strings.Join([]string{
		strings.TrimSpace(tenantID),
		machineID,
		strings.Join(macs, ","),
	}, "|")

	sum := sha256.Sum256([]byte(raw))
	hashHex := hex.EncodeToString(sum[:])

	id := uuid.NewSHA1(namespace, []byte(raw)).String()

	return Result{
		AgentID:   id,
		Hash:      hashHex,
		MachineID: machineID,
		MACs:      macs,
	}
}

// physicalMACs returns lowercased MACs from likely-physical interfaces, sorted.
// Includes interfaces regardless of up/down state so a turned-off WiFi card
// does not change the fingerprint between boots.
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
