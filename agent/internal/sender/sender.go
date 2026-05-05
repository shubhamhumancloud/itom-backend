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

	"github.com/itom-mini/agent/internal/collector"
	"github.com/itom-mini/agent/internal/info"
	"github.com/itom-mini/agent/internal/logger"
)

type PostMetricsDecision int

const (
	MetricsCommitted PostMetricsDecision = iota
	MetricsRetry
	MetricsDrop
)

type Sender struct {
	metricsEndpoint   string
	heartbeatEndpoint string
	registerEndpoint  string
	agentID           string
	tenantID          string
	client            *http.Client
	log               *logger.Logger
}

type metricsPayload struct {
	AgentID    string               `json:"agentId"`
	RequestID  string               `json:"requestId,omitempty"`
	Samples    []collector.Sample   `json:"samples"`
}

type heartbeatPayload struct {
	AgentID         string    `json:"agentId"`
	Timestamp       time.Time `json:"timestamp"`
	AgentVersion    string    `json:"agentVersion,omitempty"`
	UptimeSeconds   int64     `json:"uptimeSeconds,omitempty"`
}

type registerPayload struct {
	AgentID      string `json:"agentId"`
	TenantID     string `json:"tenantId,omitempty"`
	AgentVersion string `json:"agentVersion"`
	info.Device
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}
}

func New(serverURL, agentID, tenantID string, log *logger.Logger) *Sender {
	base := strings.TrimRight(serverURL, "/")
	return &Sender{
		metricsEndpoint:   base + "/v1/metrics",
		heartbeatEndpoint: base + "/v1/agents/heartbeat",
		registerEndpoint:  base + "/v1/agents/register",
		agentID:           agentID,
		tenantID:          tenantID,
		client:            newHTTPClient(),
		log:               log,
	}
}

func (s *Sender) Register(ctx context.Context, version string, d info.Device) error {
	_, code, err := s.postJSON(ctx, s.registerEndpoint, registerPayload{
		AgentID:      s.agentID,
		TenantID:     s.tenantID,
		AgentVersion: version,
		Device:       d,
	}, nil)
	if err != nil {
		return err
	}
	if code >= 200 && code < 300 {
		return nil
	}
	return fmt.Errorf("register: unexpected status %d", code)
}

// PostMetricsBatch sends a batch with idempotency header + body field.
func (s *Sender) PostMetricsBatch(
	ctx context.Context,
	samples []collector.Sample,
	requestID string,
) (PostMetricsDecision, error) {
	if len(samples) == 0 {
		return MetricsCommitted, nil
	}
	headers := map[string]string{
		"X-Request-Id": requestID,
	}
	body, code, err := s.postJSON(ctx, s.metricsEndpoint, metricsPayload{
		AgentID:   s.agentID,
		RequestID: requestID,
		Samples:   samples,
	}, headers)
	if err != nil {
		return MetricsRetry, err
	}
	if code >= 200 && code < 300 {
		var resp struct {
			Accepted int    `json:"accepted"`
			Reason     string `json:"reason,omitempty"`
		}
		_ = json.Unmarshal(body, &resp)
		if resp.Reason == "duplicate" {
			return MetricsCommitted, nil
		}
		if resp.Accepted > 0 {
			return MetricsCommitted, nil
		}
		// unexpected 2xx body — retry to avoid data loss
		return MetricsRetry, fmt.Errorf("metrics: ambiguous 2xx body: %s", string(body))
	}
	if code == 429 || code >= 500 {
		return MetricsRetry, fmt.Errorf("metrics: status %d", code)
	}
	if code >= 400 && code < 500 {
		return MetricsDrop, fmt.Errorf("metrics: client error %d: %s", code, string(body))
	}
	return MetricsRetry, fmt.Errorf("metrics: status %d", code)
}

// PostHeartbeat sends a heartbeat; failures should be logged by the caller.
func (s *Sender) PostHeartbeat(
	ctx context.Context,
	version string,
	uptime time.Duration,
	requestID string,
) error {
	headers := map[string]string{"X-Request-Id": requestID}
	body, code, err := s.postJSON(ctx, s.heartbeatEndpoint, heartbeatPayload{
		AgentID:        s.agentID,
		Timestamp:      time.Now().UTC(),
		AgentVersion:   version,
		UptimeSeconds:   int64(uptime.Seconds()),
	}, headers)
	if err != nil {
		return err
	}
	if code >= 200 && code < 300 {
		var resp struct {
			Accepted bool   `json:"accepted"`
			Reason   string `json:"reason,omitempty"`
		}
		_ = json.Unmarshal(body, &resp)
		return nil
	}
	return fmt.Errorf("heartbeat: status %d: %s", code, string(body))
}

func (s *Sender) postJSON(
	ctx context.Context,
	url string,
	payload any,
	extraHeaders map[string]string,
) ([]byte, int, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return respBody, resp.StatusCode, nil
}
