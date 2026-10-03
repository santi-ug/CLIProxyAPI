package access

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// IsLoopbackAddress ignores forwarding headers and accepts only numeric socket peers.
func IsLoopbackAddress(address string) bool {
	peer, err := netip.ParseAddrPort(address)
	return err == nil && peer.Addr().Unmap().IsLoopback()
}

func IsLoopbackPeer(r *http.Request) bool {
	return r != nil && IsLoopbackAddress(r.RemoteAddr)
}

// IsTrustedLoopbackRequest protects the keyless local API against browser requests and
// DNS rebinding. Extra hosts are exact names owned by a private reverse proxy, never wildcards.
// Do not expose a trusted reverse proxy through Tailscale Funnel or another public tunnel.
func IsTrustedLoopbackRequest(r *http.Request, hosts []string) bool {
	if !IsLoopbackPeer(r) {
		return false
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	allowed := host == "localhost" || host == "127.0.0.1" || host == "::1"
	for _, extra := range hosts {
		allowed = allowed || host == strings.ToLower(strings.TrimSpace(extra))
	}
	if !allowed {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 {
		return false
	}
	origin, err := url.Parse(origins[0])
	if err != nil || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return origin.Scheme == scheme && origin.Host == r.Host
}
