// Package wsclient is the agent's WebSocket transport for sending metrics and
// receiving server-pushed updates. It is responsible for:
//
//  1. Dialing wss://server/v1/ws and saying `hello` first.
//  2. Reconnecting with jittered exponential backoff after any disconnect.
//  3. Routing inbound `welcome` / `ack` / `error` / `config_update` messages.
//  4. Detecting half-open connections via the WebSocket pong from the server's
//     ping (gorilla/websocket handles pongs by extending the read deadline).
//
// Concurrency model
// -----------------
// One reader goroutine: blocks in ReadMessage and dispatches to handlers.
// One writer goroutine: serialises all outbound writes (gorilla allows only
// one concurrent writer). Callers push messages onto sendCh.
//
// One control loop (Run): owns the connection lifecycle. When the reader or
// writer exits (any error), Run cleans up and reconnects after a backoff.
package wsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/itom-mini/agent/internal/collector"
	"github.com/itom-mini/agent/internal/logger"
	"github.com/itom-mini/agent/internal/wsproto"
)

// Server-side ping cadence; we expect a ping at most every 30 s. If the read
// deadline exceeds this by a comfortable margin, declare the connection dead.
const (
	readTimeout  = 75 * time.Second
	writeTimeout = 10 * time.Second

	maxBackoff     = 60 * time.Second
	initialBackoff = 1 * time.Second
	jitterFraction = 0.25 // ±25%
)

// AckCallback is invoked when the server acks a metrics batch. result is one
// of wsproto.AckCommitted / AckDuplicate / AckRejected.
type AckCallback func(requestID, result, message string)

// ReassignCallback is invoked when the server replies with `welcome` and the
// canonical agentId differs from the one we sent. The caller must persist the
// new id (config file).
type ReassignCallback func(newAgentID string)

// Client manages exactly one logical connection to the backend (with
// automatic reconnects under the hood).
type Client struct {
	wsURL           string
	agentID         string
	agentVersion    string
	fingerprintHash string

	log *logger.Logger

	// Outbound queue. Buffered so a single transient write failure does not
	// block the producer immediately. If the buffer fills the producer
	// blocks — that's the desired backpressure (the SQLite buffer absorbs).
	sendCh chan []byte

	mu        sync.Mutex
	conn      *websocket.Conn // current connection, may be nil while reconnecting
	connected bool

	// Awaiting acks: requestId → channel that receives a single Ack.
	pending sync.Map // map[string]chan wsproto.Ack

	onAck      AckCallback
	onReassign ReassignCallback
}

type Config struct {
	ServerURL       string // http(s)://host:port — we'll convert to ws(s)
	AgentID         string
	AgentVersion    string
	FingerprintHash string
	OnAck           AckCallback
	OnReassign      ReassignCallback
	Logger          *logger.Logger
}

func New(cfg Config) (*Client, error) {
	u, err := toWSURL(cfg.ServerURL)
	if err != nil {
		return nil, err
	}
	if cfg.OnAck == nil {
		cfg.OnAck = func(string, string, string) {}
	}
	if cfg.OnReassign == nil {
		cfg.OnReassign = func(string) {}
	}
	return &Client{
		wsURL:           u,
		agentID:         cfg.AgentID,
		agentVersion:    cfg.AgentVersion,
		fingerprintHash: cfg.FingerprintHash,
		log:             cfg.Logger,
		sendCh:          make(chan []byte, 64),
		onAck:           cfg.OnAck,
		onReassign:      cfg.OnReassign,
	}, nil
}

// IsConnected reports whether the client currently has a live, post-`welcome`
// session. Senders should check this before queueing time-sensitive work.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// SendMetrics queues a metrics frame and waits up to `timeout` for the
// server's ack. Returns the ack result and any error. If the client is
// disconnected at queue time, returns an error immediately so the caller can
// keep the samples in the buffer.
func (c *Client) SendMetrics(
	ctx context.Context,
	samples []collector.Sample,
	requestID string,
	timeout time.Duration,
) (string, error) {
	msg := wsproto.Metrics{
		Type:      wsproto.TypeMetrics,
		RequestID: requestID,
		Samples:   samples,
	}
	return c.SendAcked(ctx, requestID, msg, timeout)
}

// SendAcked is the generic send: queue any JSON-marshalable message that
// embeds a `requestId`, then wait for an ack. Used by all observability
// collectors (processes, battery, sensors, disk-health, gpu, software).
//
// Best-effort: if the client is not connected, returns an error immediately.
// Callers should NOT retry — the next collector tick will sample fresh data.
func (c *Client) SendAcked(
	ctx context.Context,
	requestID string,
	msg any,
	timeout time.Duration,
) (string, error) {
	if !c.IsConnected() {
		return "", errors.New("ws not connected")
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	ackCh := make(chan wsproto.Ack, 1)
	c.pending.Store(requestID, ackCh)
	defer c.pending.Delete(requestID)

	select {
	case c.sendCh <- raw:
	case <-ctx.Done():
		return "", ctx.Err()
	}

	select {
	case ack := <-ackCh:
		return ack.Result, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("ack timeout after %s", timeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Run blocks until ctx is cancelled. It owns the dial-read-write-reconnect
// state machine; call it once from a dedicated goroutine.
func (c *Client) Run(ctx context.Context) {
	// Random delay up to 5s on the very first connect attempt to spread
	// thundering-herd at deploy time.
	jitter := time.Duration(rand.Int64N(int64(5 * time.Second)))
	c.log.Info("ws initial connect delay", "delay", jitter.String())
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
			c.log.Warn("ws session ended", "err", err)
		}
		if ctx.Err() != nil {
			return
		}

		// Backoff with jitter before next attempt.
		sleep := withJitter(backoff)
		c.log.Info("ws reconnecting", "in", sleep.String())
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// runOnce performs one full session: dial, hello/welcome, then concurrently
// read and write until something fails. Returns the error that caused the
// session to end (or nil on graceful close).
func (c *Client) runOnce(parent context.Context) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.DialContext(parent, c.wsURL, http.Header{
		"User-Agent": []string{"itom-agent/" + c.agentVersion},
	})
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.wsURL, err)
	}
	c.log.Info("ws connected", "url", c.wsURL)

	// The server sends a WebSocket ping every 30s. Each ping we receive
	// pushes the read deadline forward. PingHandler (not PongHandler) is the
	// one that fires on incoming pings — the agent never receives pongs in
	// this protocol because the agent never sends pings, so a PongHandler
	// would never fire and the deadline would never extend.
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPingHandler(func(appData string) error {
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return err
		}
		// Replicate gorilla's default: reply with a pong so the server's
		// liveness check stays happy.
		err := conn.WriteControl(
			websocket.PongMessage,
			[]byte(appData),
			time.Now().Add(writeTimeout),
		)
		if err == websocket.ErrCloseSent {
			return nil
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		return err
	})

	// Send hello as the very first frame.
	hello := wsproto.Hello{
		Type:            wsproto.TypeHello,
		AgentID:         c.agentID,
		AgentVersion:    c.agentVersion,
		FingerprintHash: c.fingerprintHash,
	}
	helloBytes, _ := json.Marshal(hello)
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := conn.WriteMessage(websocket.TextMessage, helloBytes); err != nil {
		_ = conn.Close()
		return fmt.Errorf("write hello: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.connected = false // not until we receive welcome
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.connected = false
		c.mu.Unlock()
		_ = conn.Close()
	}()

	// Session-scoped context. Either reader or writer error cancels both.
	sessCtx, cancel := context.WithCancel(parent)
	defer cancel()

	errCh := make(chan error, 2)

	go func() { errCh <- c.readerLoop(sessCtx, conn, cancel) }()
	go func() { errCh <- c.writerLoop(sessCtx, conn) }()

	// Return on first error.
	err = <-errCh
	cancel()
	// Drain the second goroutine so it cleans up before we close conn.
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

		var env wsproto.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			c.log.Warn("ws bad frame", "err", err)
			continue
		}

		switch env.Type {
		case wsproto.TypeWelcome:
			var w wsproto.Welcome
			if err := json.Unmarshal(raw, &w); err != nil {
				c.log.Warn("welcome unmarshal", "err", err)
				continue
			}
			c.handleWelcome(w)
		case wsproto.TypeAck:
			var a wsproto.Ack
			if err := json.Unmarshal(raw, &a); err != nil {
				c.log.Warn("ack unmarshal", "err", err)
				continue
			}
			c.handleAck(a)
		case wsproto.TypeError:
			var e wsproto.Error
			_ = json.Unmarshal(raw, &e)
			c.log.Error("ws server error", "code", e.Code, "msg", e.Message)
			// Don't cancel — let the server close the socket. ReadMessage
			// will return an error on the next iteration.
		case wsproto.TypeConfigUpdate:
			c.log.Info("config_update received (handler not yet implemented)")
		default:
			c.log.Warn("ws unknown frame type", "type", env.Type)
		}
	}
}

func (c *Client) writerLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		select {
		case <-ctx.Done():
			// Try a clean close frame so the server logs a normal disconnect.
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
	if w.Reassigned && w.AgentID != "" && w.AgentID != c.agentID {
		c.log.Info("agentId reassigned by server", "old", c.agentID, "new", w.AgentID)
		c.agentID = w.AgentID
		c.onReassign(w.AgentID)
	}
	c.log.Info("ws welcome",
		"agentId", w.AgentID,
		"reassigned", w.Reassigned,
		"heartbeatSec", w.HeartbeatIntervalSeconds)
}

func (c *Client) handleAck(a wsproto.Ack) {
	c.onAck(a.RequestID, a.Result, a.Message)
	if v, ok := c.pending.Load(a.RequestID); ok {
		ackCh := v.(chan wsproto.Ack)
		select {
		case ackCh <- a:
		default:
			// Receiver already gave up (timeout); drop the ack.
		}
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
		// already a ws scheme
	default:
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if !strings.HasSuffix(u.Path, "/v1/ws") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/ws"
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
