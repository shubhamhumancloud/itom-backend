package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/itom-mini/agent/internal/collector"
	"github.com/itom-mini/agent/internal/info"
	"github.com/itom-mini/agent/internal/logger"
)

type Sender struct {
	metricsEndpoint  string
	registerEndpoint string
	agentID          string
	client           *http.Client
	log              *logger.Logger
}

type batch struct {
	AgentID string             `json:"agentId"`
	Samples []collector.Sample `json:"samples"`
}

type registerPayload struct {
	AgentID      string `json:"agentId"`
	AgentVersion string `json:"agentVersion"`
	info.Device
}

func New(serverURL, agentID string, log *logger.Logger) *Sender {
	base := strings.TrimRight(serverURL, "/")
	return &Sender{
		metricsEndpoint:  base + "/v1/metrics",
		registerEndpoint: base + "/v1/agents/register",
		agentID:          agentID,
		client:           &http.Client{Timeout: 10 * time.Second},
		log:              log,
	}
}

func (s *Sender) Register(ctx context.Context, version string, d info.Device) error {
	return s.post(ctx, s.registerEndpoint, registerPayload{
		AgentID:      s.agentID,
		AgentVersion: version,
		Device:       d,
	})
}

func (s *Sender) Send(ctx context.Context, sample collector.Sample) error {
	return s.post(ctx, s.metricsEndpoint, batch{
		AgentID: s.agentID,
		Samples: []collector.Sample{sample},
	})
}

func (s *Sender) post(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
}
