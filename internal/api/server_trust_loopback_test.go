package api

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/redisqueue"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// tailnetPeer stands in for a remote client. It is also listed in trusted-proxies so gin's
// ClientIP() would believe a forged X-Forwarded-For; trust-loopback must not.
const tailnetPeer = "100.101.102.103"

func newTrustLoopbackTestServer(t *testing.T, trust bool) *Server {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")
	server := newTestServerWithConfig(t, &proxyconfig.Config{
		SDKConfig:      sdkconfig.SDKConfig{APIKeys: []string{"test-key"}},
		TrustLoopback:  trust,
		TrustedProxies: []string{tailnetPeer},
		WebsocketAuth:  true,
	})
	server.AttachWebsocketRoute("/v1/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			return
		}
		_ = conn.Close()
	}))
	return server
}

func serveFromPeer(server *Server, method, path, remoteAddr string, header http.Header) int {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr
	req.Host = "localhost"
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	recorder := httptest.NewRecorder()
	server.engine.ServeHTTP(recorder, req)
	return recorder.Code
}

// dialWebsocket upgrades over a real loopback socket, so the server sees a 127.0.0.1 peer.
func dialWebsocket(t *testing.T, server *Server, path string) int {
	t.Helper()
	httpServer := httptest.NewServer(server.engine)
	t.Cleanup(httpServer.Close)
	conn, resp, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpServer.URL, "http")+path, nil)
	if errDial == nil {
		_ = conn.Close()
		return http.StatusSwitchingProtocols
	}
	if resp == nil {
		t.Fatalf("dial %s: %v", path, errDial)
	}
	return resp.StatusCode
}

func TestTrustLoopbackSkipsKeyChecksForLoopbackPeer(t *testing.T) {
	server := newTrustLoopbackTestServer(t, true)

	for _, peer := range []string{"127.0.0.1:52000", "[::1]:52000"} {
		for _, route := range []struct {
			method, path string
			want         int
		}{
			{http.MethodGet, "/v1/models", http.StatusOK},
			{http.MethodGet, "/v1beta/models", http.StatusOK},
			// 503 means the request got past auth to the unconfigured live relay.
			{http.MethodPost, "/v1/realtime/calls", http.StatusServiceUnavailable},
			// No management secret-key is configured at all.
			{http.MethodGet, "/v0/management/config", http.StatusOK},
			{http.MethodGet, "/v8/management/credentials", http.StatusOK},
		} {
			if got := serveFromPeer(server, route.method, route.path, peer, nil); got != route.want {
				t.Errorf("%s %s from %s = %d, want %d", route.method, route.path, peer, got, route.want)
			}
		}
	}

	for _, path := range []string{"/v1/ws", "/v1/responses"} {
		if got := dialWebsocket(t, server, path); got != http.StatusSwitchingProtocols {
			t.Errorf("websocket %s from loopback = %d, want upgrade", path, got)
		}
	}
}

func TestTrustLoopbackRejectsRemotePeerWithForgedHeaders(t *testing.T) {
	server := newTrustLoopbackTestServer(t, true)
	forged := http.Header{
		"X-Forwarded-For": {"127.0.0.1"},
		"X-Real-Ip":       {"127.0.0.1"},
		"Upgrade":         {"websocket"},
		"Connection":      {"Upgrade"},
	}
	peer := tailnetPeer + ":52000"

	for _, route := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/v1/models", http.StatusUnauthorized},
		{http.MethodPost, "/v1/realtime/calls", http.StatusUnauthorized},
		{http.MethodGet, "/v1/ws", http.StatusUnauthorized},
		{http.MethodGet, "/v1/responses", http.StatusUnauthorized},
		{http.MethodGet, "/v0/management/config", http.StatusForbidden},
		{http.MethodGet, "/v8/management/credentials", http.StatusForbidden},
	} {
		if got := serveFromPeer(server, route.method, route.path, peer, forged); got != route.want {
			t.Errorf("%s %s from %s = %d, want %d", route.method, route.path, peer, got, route.want)
		}
	}
}

func TestTrustLoopbackOffKeepsKeyChecks(t *testing.T) {
	server := newTrustLoopbackTestServer(t, false)
	peer := "127.0.0.1:52000"

	if got := serveFromPeer(server, http.MethodGet, "/v1/models", peer, nil); got != http.StatusUnauthorized {
		t.Errorf("/v1/models from loopback = %d, want 401", got)
	}
	if got := serveFromPeer(server, http.MethodGet, "/v1/models", peer, http.Header{"Authorization": {"Bearer test-key"}}); got != http.StatusOK {
		t.Errorf("/v1/models with key = %d, want 200", got)
	}
	// Without a secret-key the management API stays unregistered, as upstream.
	if got := serveFromPeer(server, http.MethodGet, "/v0/management/config", peer, nil); got != http.StatusNotFound {
		t.Errorf("/v0/management/config without secret = %d, want 404", got)
	}
	for _, path := range []string{"/v1/ws", "/v1/responses"} {
		if got := dialWebsocket(t, server, path); got != http.StatusUnauthorized {
			t.Errorf("websocket %s from loopback without key = %d, want 401", path, got)
		}
	}

	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	withSecret := newTestServerWithConfig(t, &proxyconfig.Config{})
	if got := serveFromPeer(withSecret, http.MethodGet, "/v0/management/config", peer, nil); got != http.StatusUnauthorized {
		t.Errorf("/v0/management/config from loopback without key = %d, want 401", got)
	}
}

func TestTrustLoopbackHotReload(t *testing.T) {
	server := newTrustLoopbackTestServer(t, false)
	peer := "127.0.0.1:52000"
	check := func(wantAPI, wantManagement int) {
		t.Helper()
		if got := serveFromPeer(server, http.MethodGet, "/v1/models", peer, nil); got != wantAPI {
			t.Errorf("/v1/models = %d, want %d", got, wantAPI)
		}
		if got := serveFromPeer(server, http.MethodGet, "/v0/management/config", peer, nil); got != wantManagement {
			t.Errorf("/v0/management/config = %d, want %d", got, wantManagement)
		}
	}
	reload := func(trust bool) {
		next := *server.cfg
		next.TrustLoopback = trust
		server.UpdateClients(&next)
	}

	check(http.StatusUnauthorized, http.StatusNotFound)
	reload(true)
	check(http.StatusOK, http.StatusOK)
	reload(false)
	check(http.StatusUnauthorized, http.StatusNotFound)
}

func TestTrustLoopbackRedisSkipsAuthForLoopbackPeer(t *testing.T) {
	redisqueue.SetEnabled(false)
	t.Cleanup(func() { redisqueue.SetEnabled(false) })
	server := newTrustLoopbackTestServer(t, true)

	addr, stop := startRedisMuxListener(t, server)
	t.Cleanup(stop)
	conn, errDial := net.DialTimeout("tcp", addr, time.Second)
	if errDial != nil {
		t.Fatalf("dial: %v", errDial)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	redisqueue.Enqueue([]byte("a"))
	if errWrite := writeTestRESPCommand(conn, "RPOP", "usage"); errWrite != nil {
		t.Fatalf("write RPOP: %v", errWrite)
	}
	item, errRead := readTestRESPBulkString(bufio.NewReader(conn))
	if errRead != nil {
		t.Fatalf("read RPOP without AUTH: %v", errRead)
	}
	if string(item) != "a" {
		t.Fatalf("RPOP item = %q, want %q", item, "a")
	}
}

func TestTrustLoopbackRejectsBrowserAndRebinding(t *testing.T) {
	server := newTrustLoopbackTestServer(t, true)
	for _, path := range []string{"/v1/models", "/v0/management/config", "/v8/management/credentials", "/v1/ws", "/v1/responses"} {
		for _, attack := range []string{"origin", "host"} {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = "localhost"
			if attack == "origin" {
				req.Header.Set("Origin", "https://evil.test")
			} else {
				req.Host = "evil.test"
			}
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code < 400 {
				t.Fatalf("%s %s bypassed authentication: %d", path, attack, rr.Code)
			}
			if strings.Contains(path, "management") && rr.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("management exposed cross-origin response")
			}
		}
	}
}

func TestTrustLoopbackRedisReloadRevokesSubscription(t *testing.T) {
	server := newTrustLoopbackTestServer(t, true)
	addr, stop := startRedisMuxListener(t, server)
	defer stop()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeTestRESPCommand(conn, "SUBSCRIBE", "usage"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	// Read the subscription acknowledgement before revoking trust.
	for i := 0; i < 6; i++ {
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
	}
	next := *server.cfg
	next.TrustLoopback = false
	server.UpdateClients(&next)
	// A queued usage event may already be buffered when the socket closes.
	for i := 0; i < 65536; i++ {
		if _, err := reader.ReadByte(); err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("subscription was not closed")
			}
			return
		}
	}
	t.Fatal("subscription kept sending after revocation")
}

func TestTrustLoopbackWithoutAPIKeysStillRejectsBrowsers(t *testing.T) {
	server := newTestServerWithConfig(t, &proxyconfig.Config{TrustLoopback: true})
	server.AttachWebsocketRoute("/keyless-ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	for _, path := range []string{"/v1/models", "/keyless-ws", "/v1/responses"} {
		for _, attack := range []string{"origin", "host"} {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Host = "localhost"
			if attack == "origin" {
				req.Header.Set("Origin", "https://evil.test")
			} else {
				req.Host = "evil.test"
			}
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s without keys=%d", path, attack, rr.Code)
			}
		}
	}
	if got := serveFromPeer(server, "GET", "/v1/models", "127.0.0.1:1234", nil); got != http.StatusOK {
		t.Fatalf("trusted localhost=%d", got)
	}
}

func TestTrustLoopbackHTTPMultiplexerOrigin(t *testing.T) {
	server := newTrustLoopbackTestServer(t, true)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	httpListener := newMuxListener(listener.Addr(), 16)
	defer httpListener.Close()
	defer server.server.Close()
	go func() { _ = server.server.Serve(httpListener) }()
	go func() { _ = server.acceptMuxConnections(listener, httpListener) }()
	addr := listener.Addr().String()
	for _, path := range []string{"/v1/models", "/v0/management/config", "/v8/management/credentials"} {
		for _, origin := range []string{"http://" + addr, "https://" + addr} {
			req, err := http.NewRequest("GET", "http://"+addr+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Origin", origin)
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if origin == "http://"+addr && response.StatusCode != http.StatusOK {
				t.Fatalf("%s local HTTP origin returned %d", path, response.StatusCode)
			}
			if origin == "https://"+addr && response.StatusCode < 400 {
				t.Fatalf("%s accepted HTTPS origin over plain HTTP", path)
			}
		}
	}
}
