// Package sender handles the agent's bootstrap REST call to the backend
// (agent registration). All steady-state traffic — metrics and liveness —
// flows over the WebSocket transport in `internal/wsclient` instead.
package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/itom-mini/agent/internal/info"
	"github.com/itom-mini/agent/internal/logger"
)

type Sender struct {
	registerEndpoint string
	agentID          string
	tenantID         string
	client           *http.Client
	log              *logger.Logger
}

type registerPayload struct {
	AgentID         string `json:"agentId"`
	TenantID        string `json:"tenantId,omitempty"`
	AgentVersion    string `json:"agentVersion"`
	FingerprintHash string `json:"fingerprintHash,omitempty"`
	info.Device
}

// RegisterResponse mirrors the backend register response. When Reassigned is
// true, the agent must adopt the returned AgentID because the backend matched
// the fingerprint to an existing agent record.
type RegisterResponse struct {
	AgentID    string `json:"agentId"`
	Reassigned bool   `json:"reassigned"`
}

func New(serverURL, agentID, tenantID string, log *logger.Logger) *Sender {
	base := strings.TrimRight(serverURL, "/")
	return &Sender{
		registerEndpoint: base + "/v1/agents/register",
		agentID:          agentID,
		tenantID:         tenantID,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
		log: log,
	}
}

func (s *Sender) Register(
	ctx context.Context,
	version, fingerprintHash string,
	d info.Device,
) (*RegisterResponse, error) {
	body, code, err := s.postJSON(ctx, s.registerEndpoint, registerPayload{
		AgentID:         s.agentID,
		TenantID:        s.tenantID,
		AgentVersion:    version,
		FingerprintHash: fingerprintHash,
		Device:          d,
	})
	if err != nil {
		return nil, err
	}
	if code < 200 || code >= 300 {
		return nil, fmt.Errorf("register: unexpected status %d: %s", code, string(body))
	}
	var resp RegisterResponse
	if len(body) > 0 {
		_ = json.Unmarshal(body, &resp)
	}
	if resp.Reassigned && resp.AgentID != "" && resp.AgentID != s.agentID {
		s.agentID = resp.AgentID
	}
	return &resp, nil
}

func (s *Sender) postJSON(ctx context.Context, url string, payload any) ([]byte, int, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return respBody, resp.StatusCode, nil
}
