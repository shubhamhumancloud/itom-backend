package cidrguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestCanonicalBytes_sortsAndShapesDeterministically(t *testing.T) {
	got, err := CanonicalBytes([]string{"192.168.1.0/24", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"cidrs":["10.0.0.0/8","192.168.1.0/24"]}`
	if string(got) != want {
		t.Fatalf("canonical mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestVerifyAndLoad_acceptsGoodSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cidrs := []string{"10.0.0.0/8", "192.168.1.0/24"}
	msg, _ := CanonicalBytes(cidrs)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))

	g, err := VerifyAndLoad(pub, cidrs, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !g.AllowString("10.0.5.42") {
		t.Errorf("expected 10.0.5.42 allowed")
	}
	if g.AllowString("8.8.8.8") {
		t.Errorf("8.8.8.8 should be denied")
	}
}

func TestVerifyAndLoad_rejectsTamperedAllowlist(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cidrs := []string{"10.0.0.0/8"}
	msg, _ := CanonicalBytes(cidrs)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))

	// Caller tampered: added an extra CIDR after signing.
	_, err := VerifyAndLoad(pub, []string{"10.0.0.0/8", "8.8.8.8/32"}, sig)
	if err == nil {
		t.Fatal("expected signature mismatch error")
	}
}

func TestAllow_emptyAllowlistDeniesEverything(t *testing.T) {
	g, _ := New(nil)
	if g.AllowString("10.0.0.1") {
		t.Error("empty allowlist must deny by default")
	}
}
