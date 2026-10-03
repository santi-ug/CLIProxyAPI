package access

import (
	"net/http/httptest"
	"testing"
)

func TestIsLoopbackPeer(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       bool
	}{
		{"127.0.0.1:52000", true},
		{"[::1]:52000", true},
		{"[::ffff:127.0.0.1]:52000", true},
		{"100.101.102.103:52000", false},
		{"192.168.1.20:52000", false},
		{"[fe80::1]:52000", false},
		{"127.0.0.1", false},
		{"", false},
	}
	for _, test := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = test.remoteAddr
		if got := IsLoopbackPeer(req); got != test.want {
			t.Errorf("IsLoopbackPeer(%q) = %t, want %t", test.remoteAddr, got, test.want)
		}
	}
}

func TestTrustedLoopbackBrowserBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, peer, host, origin string
		hosts                    []string
		want                     bool
	}{
		{"native", "127.0.0.1:1234", "localhost:8317", "", nil, true},
		{"same origin", "[::1]:1234", "localhost:8317", "http://localhost:8317", nil, true},
		{"browser attack", "127.0.0.1:1234", "localhost:8317", "https://evil.test", nil, false},
		{"rebinding", "127.0.0.1:1234", "evil.test:8317", "", nil, false},
		{"different port", "127.0.0.1:1234", "localhost:8317", "http://localhost:1234", nil, false},
		{"null origin", "127.0.0.1:1234", "localhost", "null", nil, false},
		{"private proxy", "127.0.0.1:1234", "mac.tailnet.ts.net", "http://mac.tailnet.ts.net", []string{"mac.tailnet.ts.net"}, true},
		{"remote socket", "100.100.100.100:1234", "localhost", "", nil, false},
		{"mapped ipv4", "[::ffff:127.0.0.1]:1234", "127.0.0.1", "", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			if got := IsTrustedLoopbackRequest(r, tc.hosts); got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}
