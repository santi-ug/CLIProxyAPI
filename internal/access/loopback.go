package access

import (
	"net/http"
	"net/netip"
)

// IsLoopbackPeer reports whether the request's TCP peer (r.RemoteAddr) is a loopback address.
// Callers use it for the trust-loopback config flag. It deliberately ignores X-Forwarded-For,
// X-Real-IP and gin's ClientIP: those come from the client or from a local reverse proxy
// (Tailscale Serve sets X-Forwarded-For to the tailnet client), so only the socket peer counts.
func IsLoopbackPeer(r *http.Request) bool {
	if r == nil {
		return false
	}
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	return addrPort.Addr().Unmap().IsLoopback()
}
