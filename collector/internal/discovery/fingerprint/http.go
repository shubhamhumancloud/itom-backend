package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// probeHTTPServer does a single HEAD / against https://host:port/ and
// returns the `Server:` header. We expect short, clean values like:
//
//	Server: nginx                        (most generic; uninformative)
//	Server: Apache                       (uninformative)
//	Server: Mikrotik HttpProxy
//	Server: FortinetCloud                (occasionally on FortiGate)
//	Server: PAN-OS                       (sometimes on Palo Alto)
//
// Medium-strength signal: many vendors customise it, some don't. We
// score it conservatively in score.go.
func probeHTTPServer(ctx context.Context, host string, port int, timeout time.Duration) string {
	// One-off HTTP client — no shared transport. We want each probe to
	// open + close so accidental pipelining can't carry state across
	// devices and so cert verification is per-probe.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
	}
	c := &http.Client{Transport: tr, Timeout: timeout}

	url := fmt.Sprintf("https://%s:%d/", host, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return ""
	}
	// HEAD is preferred — many appliance landing pages are several MiB
	// of inline JS. Some devices ignore HEAD and return 405; fall back
	// to GET if so.
	resp, err := c.Do(req)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed {
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp2, err := c.Do(req)
		if err != nil || resp2 == nil {
			return ""
		}
		defer resp2.Body.Close()
		return strings.TrimSpace(resp2.Header.Get("Server"))
	}
	return strings.TrimSpace(resp.Header.Get("Server"))
}
