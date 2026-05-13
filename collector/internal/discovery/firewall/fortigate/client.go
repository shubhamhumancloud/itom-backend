package fortigate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// httpClient is a thin wrapper around net/http that handles:
//   - bearer-token auth (FortiOS REST-API admin token)
//   - VDOM scoping via ?vdom=... on every URL
//   - pinned TLS certificate by SHA-256 fingerprint (per-tenant trust)
//   - pagination loop for cmdb endpoints
//
// We intentionally don't use FortinetCloud/Fortinet's SDK — it's geared
// for Terraform-style config writes, not bulk read-only ingestion.
type httpClient struct {
	base   string // https://host:port
	token  string
	httpc  *http.Client
}

// pageSize is the cmdb pagination chunk. FortiOS caps `count` at 1000;
// stay below to leave room for response bloat.
const pageSize = 500

// newHTTPClient builds the HTTP client and (optionally) a pinned-cert
// TLS verifier. An empty pinSHA256 falls back to the system trust store
// — fine for lab gear, never for production.
func newHTTPClient(host, token, pinSHA256 string) (*httpClient, error) {
	host = strings.TrimRight(host, "/")
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
		// FortiOS REST has been known to wedge under aggressive keepalives;
		// the default settings are safe but we set a tight TLS handshake
		// timeout so a misbehaving box fails fast.
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
	}
	if pinSHA256 != "" {
		want, err := normaliseFingerprint(pinSHA256)
		if err != nil {
			return nil, fmt.Errorf("bad tls fingerprint: %w", err)
		}
		// We skip the default verification (the cert is almost always
		// self-signed) but enforce a fingerprint match in
		// VerifyPeerCertificate. Either matches or we close the connection.
		tr.TLSClientConfig.InsecureSkipVerify = true
		tr.TLSClientConfig.VerifyPeerCertificate = pinnedVerifier(want)
	}

	return &httpClient{
		base:  host,
		token: token,
		httpc: &http.Client{
			Transport: tr,
			Timeout:   60 * time.Second,
		},
	}, nil
}

// get performs a single GET with auth + vdom scoping and unmarshals the
// body into dst. Non-2xx responses are returned as a typed *apiError so
// the caller can distinguish 401 (rotate credential) from 5xx (retry).
func (c *httpClient) get(ctx context.Context, path, vdom string, dst any) error {
	u, err := c.urlFor(path, vdom, nil)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodGet, u, dst)
}

// getPaginated walks a cmdb collection endpoint that supports start+count.
// It accumulates every page into `dst.Results`. Caller passes a pointer to
// the envelope so we can write the merged slice back.
//
// The signature uses a closure (`appendPage`) instead of generics because
// each page envelope holds a different concrete slice type and Go's
// generics don't make this much cleaner for our two-level decoding case.
func (c *httpClient) getPaginated(
	ctx context.Context,
	path, vdom string,
	appendPage func(rawResults json.RawMessage) error,
) error {
	start := 0
	for {
		u, err := c.urlFor(path, vdom, map[string]string{
			"start": strconv.Itoa(start),
			"count": strconv.Itoa(pageSize),
		})
		if err != nil {
			return err
		}

		var env struct {
			Status  string          `json:"status"`
			Results json.RawMessage `json:"results"`
			Total   int             `json:"total"`
			Size    int             `json:"size"`
		}
		if err := c.do(ctx, http.MethodGet, u, &env); err != nil {
			return err
		}
		if env.Status != "" && env.Status != "success" {
			return fmt.Errorf("fortigate %s returned status=%s", path, env.Status)
		}
		if err := appendPage(env.Results); err != nil {
			return fmt.Errorf("decode page at start=%d: %w", start, err)
		}
		// Stop when this page is short. `total` is unreliable on some
		// FortiOS versions, so we trust `size` to be the actual count
		// returned in this page.
		if env.Size < pageSize || env.Size == 0 {
			return nil
		}
		start += env.Size
	}
}

func (c *httpClient) do(ctx context.Context, method, u string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("fortigate %s %s: %w", method, u, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap
	if resp.StatusCode/100 != 2 {
		apiErr := &apiError{
			Method:     method,
			URL:        u,
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
		// 401 means "credential rotated/revoked". Wrap with the shared
		// firewall.AuthError so the generic driver adapter (and any
		// other firewall.IsAuth caller) can short-circuit the job.
		if resp.StatusCode == http.StatusUnauthorized {
			return &firewall.AuthError{Wrapped: apiErr}
		}
		return apiErr
	}
	if dst == nil {
		return nil
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("fortigate decode %s: %w", u, err)
	}
	return nil
}

func (c *httpClient) urlFor(path, vdom string, extra map[string]string) (string, error) {
	u, err := url.Parse(c.base + path)
	if err != nil {
		return "", err
	}
	q := u.Query()
	// FortiOS REST requires a vdom query param even on single-VDOM boxes.
	// "*" returns rows from every VDOM but the response shape changes; we
	// always pin to a concrete VDOM and let the caller fan out.
	if vdom != "" {
		q.Set("vdom", vdom)
	}
	for k, v := range extra {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// apiError carries enough context for the dispatcher to react. 401 means
// "credential rotated" — surface to BE as a credential-error so the user
// gets paged instead of an infinite retry loop.
type apiError struct {
	Method     string
	URL        string
	StatusCode int
	Body       string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("fortigate %s %s -> %d: %s", e.Method, e.URL, e.StatusCode, truncate(e.Body, 256))
}

// isFortigateAPIAuthErr reports whether the underlying transport error
// is a 401 from the FortiGate REST API. Used internally for messaging
// — the canonical "is this auth?" check at the package boundary uses
// firewall.IsAuth which understands *firewall.AuthError.
func isFortigateAPIAuthErr(err error) bool {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.StatusCode == http.StatusUnauthorized
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func normaliseFingerprint(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ToLower(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("want %d bytes, got %d", sha256.Size, len(b))
	}
	return b, nil
}

// pinnedVerifier returns a TLS VerifyPeerCertificate function that
// accepts only certificates whose SHA-256 fingerprint matches `want`.
// Self-signed customer firewall certs are the norm, so we cannot rely
// on the system trust store — but blanket InsecureSkipVerify with no
// pin would let a MITM swap the firewall for anything.
func pinnedVerifier(want []byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("tls: peer sent no certificate")
		}
		got := sha256.Sum256(rawCerts[0])
		// constant-time compare not strictly necessary for a public fingerprint
		// but cheap insurance.
		if !bytesEqual(got[:], want) {
			return fmt.Errorf(
				"tls: leaf cert fingerprint mismatch (got %x, want %x)",
				got, want,
			)
		}
		return nil
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
