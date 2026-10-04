package management

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Exercise both trusted-loopback and keyed authorization while hot reload swaps
// configurations. Run with -race: every authentication read must share SetConfig's lock.
func TestManagementAuthorizationConcurrentConfigReload(t *testing.T) {
	h := &Handler{cfg: &config.Config{}, failedAttempts: make(map[string]*attemptInfo), envSecret: "fixture-key"}
	engine := gin.New()
	engine.GET("/check", h.Middleware(), func(c *gin.Context) { c.Status(http.StatusOK) })
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 500; i++ {
			h.SetConfig(&config.Config{TrustLoopback: i%2 == 0, TrustLoopbackHosts: []string{"localhost"}})
		}
	}()
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 200; i++ {
				req := httptest.NewRequest(http.MethodGet, "http://localhost/check", nil)
				req.RemoteAddr = "127.0.0.1:50000"
				req.Header.Set("X-Management-Key", "fixture-key")
				rec := httptest.NewRecorder()
				engine.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("authorization=%d body=%s", rec.Code, rec.Body.String())
					return
				}
				allowed, _, message := h.AuthenticateManagementKey("127.0.0.1", true, "fixture-key")
				if !allowed {
					t.Errorf("key authorization=%s", message)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}
