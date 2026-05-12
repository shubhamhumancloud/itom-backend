package wsclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/itom-mini/collector/internal/discovery/device"
)

// HTTPCredentialResolver fetches decrypted credentials over HTTPS from
// the BE's /v1/discovery/credentials/:id/decrypt endpoint. The BE
// writes one audit_log row per decrypt; the plaintext lives only in
// this collector's RAM for the duration of one job.
type HTTPCredentialResolver struct {
	BaseURL    string // http(s)://server[:port]
	AuthHeader string // per-collector bearer (same one used on WS handshake)
	// CollectorID is sent in the X-Collector-Id header so the BE can
	// verify the bearer against the right row in constant time.
	CollectorID string
	HTTPClient  *http.Client
}

// NewHTTPCredentialResolver builds a resolver with a sensible default
// timeout. Pass nil for HTTPClient to accept the default.
func NewHTTPCredentialResolver(baseURL, authHeader, collectorID string, httpc *http.Client) *HTTPCredentialResolver {
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPCredentialResolver{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		AuthHeader:  authHeader,
		CollectorID: collectorID,
		HTTPClient:  httpc,
	}
}

// Resolve implements CredentialResolver.
//
// The BE response carries the firewall connection target alongside the
// decrypted secret because (a) the credential is logically tied to one
// firewall and (b) keeping host+secret in one round-trip means one
// audit_log entry covers the whole "I used this credential" event.
func (r *HTTPCredentialResolver) Resolve(
	ctx context.Context,
	tenantID, credentialID string,
) (device.Creds, error) {
	url := fmt.Sprintf("%s/v1/discovery/credentials/%s/decrypt", r.BaseURL, credentialID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return device.Creds{}, err
	}
	req.Header.Set("Authorization", "Bearer "+r.AuthHeader)
	req.Header.Set("X-Tenant-Id", tenantID)
	req.Header.Set("X-Collector-Id", r.CollectorID)

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return device.Creds{}, fmt.Errorf("decrypt credential: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return device.Creds{}, fmt.Errorf("decrypt credential %s: %d: %s", credentialID, resp.StatusCode, string(body))
	}
	var out struct {
		Host                 string `json:"host"`
		Username             string `json:"username"`
		Password             string `json:"password"`
		APIKey               string `json:"apiKey"`
		TLSFingerprintSHA256 string `json:"tlsFingerprintSha256"`
		SNMPCommunity        string `json:"snmpCommunity"`
		SNMPv3Username       string `json:"snmpv3Username"`
		SNMPv3AuthProtocol   string `json:"snmpv3AuthProtocol"`
		SNMPv3AuthKey        string `json:"snmpv3AuthKey"`
		SNMPv3PrivProtocol   string `json:"snmpv3PrivProtocol"`
		SNMPv3PrivKey        string `json:"snmpv3PrivKey"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return device.Creds{}, fmt.Errorf("decode credential: %w", err)
	}
	return device.Creds{
		Host:                 out.Host,
		Username:             out.Username,
		Password:             out.Password,
		APIKey:               out.APIKey,
		TLSFingerprintSHA256: out.TLSFingerprintSHA256,
		SNMPCommunity:        out.SNMPCommunity,
		SNMPv3Username:       out.SNMPv3Username,
		SNMPv3AuthProtocol:   out.SNMPv3AuthProtocol,
		SNMPv3AuthKey:        out.SNMPv3AuthKey,
		SNMPv3PrivProtocol:   out.SNMPv3PrivProtocol,
		SNMPv3PrivKey:        out.SNMPv3PrivKey,
	}, nil
}
