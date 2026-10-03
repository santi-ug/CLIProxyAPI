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
