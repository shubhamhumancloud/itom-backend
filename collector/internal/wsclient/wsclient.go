// Package wsclient is the collector's WebSocket transport to the
// discovery surface of the backend (`/v1/discovery/ws`). It owns the
// dial-hello-read/write-reconnect state machine and dispatches inbound
// ScanJobAssign frames to a registered Handler.
//
// This is intentionally a separate transport from the agent's
// `backend/agent/internal/wsclient`: same gorilla/websocket library and
// the same reconnect/backoff shape, but a different frame envelope
// (kind+payload, not a flat `type` field), a different path, and a
// different role. Keeping them apart means changes to host-metrics
// framing never accidentally break discovery and vice versa.
package wsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/itom-mini/collector/internal/wsproto"
)

const (
	readTimeout  = 75 * time.Second
	writeTimeout = 10 * time.Second

	maxBackoff     = 60 * time.Second
	initialBackoff = 1 * time.Second
	jitterFraction = 0.25 // ±25%
)

// Logger is the tiny subset of logging the client needs. The collectord
// command supplies a concrete one — keeping the interface here means we
// can drop a fake into unit tests without dragging in slog.
type Logger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

// Handler runs a scan job. The dispatcher (in this same package) gives
// it the parsed assignment and a SendChunk callback so the job can stream
// observations back over the same socket without owning the writer.
//
// Returning a non-nil error causes the client to send ScanJobError and
// close out the job; returning nil with non-zero observationCount sends
// ScanJobDone.
type Handler interface {
	Run(
		ctx context.Context,
		assign wsproto.ScanJobAssign,
		emit func(chunk wsproto.ScanJobChunk) error,
	) (observationCount int, err error)
}

// Config is the input to New.
type Config struct {
	ServerURL   string // http(s):// — converted to ws(s) automatically
	TenantID    string
	CollectorID string
	// AuthToken is the bearer the BE issued at collector creation. We send
	// it on the WS handshake (Authorization + Sec-WebSocket-Protocol so
	// any reverse proxy that strips one still passes the other).
	AuthToken string
	Version   string
	Handler   Handler
	Logger    Logger
}

// Client manages exactly one logical connection (with automatic
// reconnects under the hood) and dispatches jobs to Handler.
type Client struct {
	wsURL       string
	tenantID    string
	collectorID string
	authToken   string
	version     string

	handler Handler
	log     Logger

	sendCh chan []byte

	mu        sync.Mutex
	conn      *websocket.Conn
	connected bool

	// In-flight jobs keyed by jobId. Cancelling a context cancels the
	// running pillar — used on disconnect so a job that was mid-flight
	// at the time of a network blip is torn down cleanly. (The server
	// re-dispatches on the next pickup; the partial chunks already sent
	// are kept and merged by fusion in chapter 4.)
	jobs sync.Map // map[string]context.CancelFunc
}

// New constructs a Client. It does NOT dial — call Run.
func New(cfg Config) (*Client, error) {
	if cfg.Handler == nil {
		return nil, errors.New("wsclient: Handler is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("wsclient: Logger is required")
	}
	if cfg.CollectorID == "" || cfg.TenantID == "" {
		return nil, errors.New("wsclient: CollectorID and TenantID are required")
	}
	u, err := toWSURL(cfg.ServerURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		wsURL:       u,
		tenantID:    cfg.TenantID,
		collectorID: cfg.CollectorID,
		authToken:   cfg.AuthToken,
		version:     cfg.Version,
		handler:     cfg.Handler,
		log:         cfg.Logger,
		sendCh:      make(chan []byte, 32),
	}, nil
}

// IsConnected reports whether the client has a live, post-`welcome`
// session.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Run blocks until ctx is cancelled. Owns the dial-read-write-reconnect
// loop; call once from a dedicated goroutine.
func (c *Client) Run(ctx context.Context) {
	// Small initial jitter to avoid thundering herd if a customer site
	// power-cycles many collectors at once.
	jitter := time.Duration(rand.Int64N(int64(5 * time.Second)))
	c.log.Info("discovery ws initial connect delay", "delay", jitter.String())
	select {
	case <-time.After(jitter):
	case <-ctx.Done():
		return
	}

	backoff := initialBackoff
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		err := c.runOnce(ctx)
		if err != nil {
			c.log.Warn("discovery ws session ended", "err", err)
		}
		if ctx.Err() != nil {
			return
		}
		sleep := withJitter(backoff)
		c.log.Info("discovery ws reconnecting", "in", sleep.String())
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// runOnce performs one full session: dial, hello/welcome, then
// concurrently read and write until something fails.
func (c *Client) runOnce(parent context.Context) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		// Subprotocol = redundant carrier for the bearer in case the
		// reverse proxy strips Authorization (some do, since auth
		// belongs on the WS frame layer in their model).
		Subprotocols: []string{"itom-collector-token." + c.authToken},
	}
	conn, _, err := dialer.DialContext(parent, c.wsURL, http.Header{
		"User-Agent":    []string{"itom-collector/" + c.version},
		"Authorization": []string{"Bearer " + c.authToken},
	})
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.wsURL, err)
	}
	c.log.Info("discovery ws connected", "url", c.wsURL)

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readTimeout))
	})

	// Send hello first.
	hello, err := wsproto.NewFrame(wsproto.KindHello, wsproto.Hello{
		CollectorID: c.collectorID,
		TenantID:    c.tenantID,
		Version:     c.version,
		Role:        "collector",
	})
	if err != nil {
		_ = conn.Close()
		return err
	}
	helloBytes, _ := json.Marshal(hello)
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := conn.WriteMessage(websocket.TextMessage, helloBytes); err != nil {
		_ = conn.Close()
		return fmt.Errorf("write hello: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.connected = false
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.connected = false
		c.mu.Unlock()
		_ = conn.Close()
		c.cancelAllJobs()
	}()

	sessCtx, cancel := context.WithCancel(parent)
	defer cancel()

	errCh := make(chan error, 2)
	go func() { errCh <- c.readerLoop(sessCtx, conn, cancel) }()
	go func() { errCh <- c.writerLoop(sessCtx, conn) }()

	err = <-errCh
	cancel()
	<-errCh
	return err
}

func (c *Client) readerLoop(
	ctx context.Context,
	conn *websocket.Conn,
	cancel context.CancelFunc,
) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, raw, err := conn.ReadMessage()
		if err != nil {
			cancel()
			return fmt.Errorf("read: %w", err)
		}
		var frame wsproto.Frame
		if err := json.Unmarshal(raw, &frame); err != nil {
			c.log.Warn("discovery ws bad frame", "err", err)
			continue
		}
		switch frame.Kind {
		case wsproto.KindWelcome:
			var w wsproto.Welcome
			if err := frame.Decode(&w); err != nil {
				c.log.Warn("welcome decode", "err", err)
				continue
			}
			c.handleWelcome(w)
		case wsproto.KindError:
			var e wsproto.Error
			_ = frame.Decode(&e)
			c.log.Error("discovery ws server error", "code", e.Code, "msg", e.Message)
			// Server will close after error; the next ReadMessage will exit.
		case wsproto.KindPing:
			var p wsproto.Ping
			_ = frame.Decode(&p)
			pong, _ := wsproto.NewFrame(wsproto.KindPong, wsproto.Pong{RequestID: p.RequestID})
			c.queueFrame(pong)
		case wsproto.KindScanJobAssign:
			var a wsproto.ScanJobAssign
			if err := frame.Decode(&a); err != nil {
				c.log.Warn("scan_job.assign decode", "err", err)
				continue
			}
			// Run jobs in their own goroutine — the reader must never
			// block on pillar work, otherwise a slow firewall could
			// starve subsequent assignments / pings.
			go c.handleAssign(ctx, a)
		default:
			c.log.Warn("discovery ws unknown frame kind", "kind", string(frame.Kind))
		}
	}
}

func (c *Client) writerLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		select {
		case <-ctx.Done():
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			_ = conn.WriteMessage(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "shutdown"),
			)
			return ctx.Err()
		case raw, ok := <-c.sendCh:
			if !ok {
				return errors.New("send channel closed")
			}
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := conn.WriteMessage(websocket.TextMessage, raw); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
	}
}

func (c *Client) handleWelcome(w wsproto.Welcome) {
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	if w.Reassigned && w.CollectorID != "" && w.CollectorID != c.collectorID {
		c.log.Warn(
			"collectorId reassigned by server",
			"old", c.collectorID, "new", w.CollectorID,
		)
		c.collectorID = w.CollectorID
	}
	c.log.Info(
		"discovery ws welcome",
		"collectorId", w.CollectorID,
		"reassigned", w.Reassigned,
		"heartbeatSec", w.HeartbeatIntervalSeconds,
	)
}

// handleAssign owns a single job from receipt to ScanJobDone/Error.
func (c *Client) handleAssign(parent context.Context, a wsproto.ScanJobAssign) {
	// Immediate ack so the BE can flip the row to `running`.
	ack, _ := wsproto.NewFrame(wsproto.KindScanJobAck, wsproto.ScanJobAck{
		JobID:       a.JobID,
		CollectorID: c.collectorID,
		AcceptedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	})
	c.queueFrame(ack)

	jobCtx, cancel := context.WithCancel(parent)
	c.jobs.Store(a.JobID, cancel)
	defer func() {
		cancel()
		c.jobs.Delete(a.JobID)
	}()

	emit := func(chunk wsproto.ScanJobChunk) error {
		chunk.JobID = a.JobID
		chunk.SessionID = a.SessionID
		f, err := wsproto.NewFrame(wsproto.KindScanJobChunk, chunk)
		if err != nil {
			return err
		}
		return c.sendFrame(jobCtx, f)
	}

	count, err := c.handler.Run(jobCtx, a, emit)
	if err != nil {
		c.log.Warn("scan job failed", "jobId", a.JobID, "err", err)
		errFrame, _ := wsproto.NewFrame(wsproto.KindScanJobError, wsproto.ScanJobError{
			JobID:  a.JobID,
			Reason: classifyError(err),
			Detail: err.Error(),
		})
		c.queueFrame(errFrame)
		return
	}
	done, _ := wsproto.NewFrame(wsproto.KindScanJobDone, wsproto.ScanJobDone{
		JobID:            a.JobID,
		SessionID:        a.SessionID,
		ObservationCount: count,
		EndedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	})
	c.queueFrame(done)
}

// queueFrame is fire-and-forget. Drops the frame if the buffer is full
// — better than blocking the reader, and the BE will time out the job
// and re-dispatch.
func (c *Client) queueFrame(f wsproto.Frame) {
	raw, err := json.Marshal(f)
	if err != nil {
		c.log.Warn("queueFrame marshal", "kind", f.Kind, "err", err)
		return
	}
	select {
	case c.sendCh <- raw:
	default:
		c.log.Warn("discovery ws send buffer full; dropping frame", "kind", f.Kind)
	}
}

// sendFrame blocks until the writer accepts the frame (or ctx is done).
// Used by the pillar's emit() callback so backpressure flows through to
// the firewall paging loop instead of dropping observations on the
// floor.
func (c *Client) sendFrame(ctx context.Context, f wsproto.Frame) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	select {
	case c.sendCh <- raw:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) cancelAllJobs() {
	c.jobs.Range(func(key, value any) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		c.jobs.Delete(key)
		return true
	})
}

// classifyError gives the BE a stable machine-readable reason. The
// detail field carries the full message for humans on the dashboard.
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "token rejected"),
		strings.Contains(msg, "401"),
		strings.Contains(msg, "rotate the api-user key"):
		return "credential_invalid"
	case strings.Contains(msg, "signature did not verify"):
		return "allowlist_signature_invalid"
	case strings.Contains(msg, "cidr"):
		return "out_of_scope"
	case strings.Contains(msg, "context canceled"),
		strings.Contains(msg, "deadline exceeded"):
		return "cancelled"
	default:
		return "internal_error"
	}
}

func toWSURL(serverURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return "", fmt.Errorf("parse server url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if !strings.HasSuffix(u.Path, "/v1/discovery/ws") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/discovery/ws"
	}
	return u.String(), nil
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func withJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	delta := float64(d) * jitterFraction
	low := float64(d) - delta
	high := float64(d) + delta
	return time.Duration(low + rand.Float64()*(high-low))
}
