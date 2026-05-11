package fingerprint

import (
	"context"
	"testing"
)

// withMockedHardware swaps the OS-specific reader for a deterministic stub
// so tests can run on any platform without touching real hardware.
func withMockedHardware(t *testing.T, uuid, serial string) {
	t.Helper()
	saved := hardwareIdentifiersFn
	hardwareIdentifiersFn = func() (string, string) { return uuid, serial }
	t.Cleanup(func() { hardwareIdentifiersFn = saved })
}

func TestComputeIsDeterministic(t *testing.T) {
	withMockedHardware(t, "ABC-DEF", "SER-001")
	a, err := Compute(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("first compute: %v", err)
	}
	b, err := Compute(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("second compute: %v", err)
	}
	if a.AgentID != b.AgentID {
		t.Fatalf("AgentID drifted: %s vs %s", a.AgentID, b.AgentID)
	}
	if a.Hash != b.Hash {
		t.Fatalf("Hash drifted: %s vs %s", a.Hash, b.Hash)
	}
}

func TestComputeNormalisesCaseAndWhitespace(t *testing.T) {
	withMockedHardware(t, "  ABC-DEF  ", "Ser-001")
	a, _ := Compute(context.Background(), "tenant-1")

	withMockedHardware(t, "abc-def", "ser-001")
	b, _ := Compute(context.Background(), "tenant-1")

	if a.AgentID != b.AgentID {
		t.Fatalf("case/whitespace not normalised: %s vs %s", a.AgentID, b.AgentID)
	}
}

func TestComputeRefusesEmptyInputs(t *testing.T) {
	withMockedHardware(t, "", "")
	if _, err := Compute(context.Background(), "tenant-1"); err == nil {
		t.Fatal("expected error when both hwUUID and hwSerial are empty")
	}
}

func TestComputeAcceptsSerialAlone(t *testing.T) {
	withMockedHardware(t, "", "SER-ONLY")
	r, err := Compute(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("expected serial-only fingerprint to succeed: %v", err)
	}
	if r.HardwareSerial != "ser-only" {
		t.Fatalf("serial not normalised: %q", r.HardwareSerial)
	}
}

func TestJoinFingerprintInputsByteIdentical(t *testing.T) {
	a := joinFingerprintInputs(" tenant ", "  UUID-ABC  ", "Serial")
	b := joinFingerprintInputs("tenant", "uuid-abc", "serial")
	if a != b {
		t.Fatalf("non-identical normalised raw: %q vs %q", a, b)
	}
}

func TestDifferentTenantsProduceDifferentIDs(t *testing.T) {
	withMockedHardware(t, "UUID", "SER")
	a, _ := Compute(context.Background(), "tenant-A")
	b, _ := Compute(context.Background(), "tenant-B")
	if a.AgentID == b.AgentID {
		t.Fatal("two tenants on the same hardware must yield different AgentIDs")
	}
}
