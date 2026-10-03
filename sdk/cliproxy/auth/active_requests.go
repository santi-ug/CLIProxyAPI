package auth

import (
	"io"
	"sync"
)

// activeRequestCounter counts upstream requests currently executing per credential.
// The zero value is ready to use.
type activeRequestCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

// begin marks one request as executing on authID. The returned release is idempotent,
// so a count can only go down once per begin and never below zero.
func (c *activeRequestCounter) begin(authID string) (release func()) {
	c.mu.Lock()
	if c.counts == nil {
		c.counts = make(map[string]int)
	}
	c.counts[authID]++
	c.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			if remaining := c.counts[authID] - 1; remaining > 0 {
				c.counts[authID] = remaining
			} else {
				delete(c.counts, authID)
			}
			c.mu.Unlock()
		})
	}
}

func (c *activeRequestCounter) get(authID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[authID]
}

// trackActive runs one synchronous upstream call while counting it as active on authID.
// The deferred release also covers panics, so the count cannot leak.
func trackActive[T any](m *Manager, authID string, call func() (T, error)) (T, error) {
	defer m.activeRequests.begin(authID)()
	return call()
}

// ActiveRequests returns how many upstream requests are executing on the credential right now.
// Unary calls count until they return; streams (including WebSocket turns) count until the
// stream ends or the attempt fails over.
func (m *Manager) ActiveRequests(authID string) int {
	if m == nil {
		return 0
	}
	return m.activeRequests.get(authID)
}

// activeRequestBody keeps raw HTTP calls active through body consumption or closure.
type activeRequestBody struct {
	io.ReadCloser
	release func()
}

func (b *activeRequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.release()
	}
	return n, err
}
func (b *activeRequestBody) Close() error {
	defer b.release()
	return b.ReadCloser.Close()
}
