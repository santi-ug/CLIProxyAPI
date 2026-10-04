package auth

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestPoolReserveDoesNotWeakenClaudeCodeOnly(t *testing.T) {
	SetClaudeCodeOnly(true)
	t.Cleanup(func() { SetClaudeCodeOnly(false) })
	for _, path := range []string{"execute", "count", "stream"} {
		t.Run(path, func(t *testing.T) {
			exec := &claudeCancellationTestExecutor{}
			m, reserve, model := newClaudeCancellationTestManager(t, exec, nil)
			reserve.Metadata["pool_role"] = "reserve"
			reserve.Metadata["pool_mode"] = "on"
			reserve.Metadata["priority"] = 200
			if _, err := m.Update(context.Background(), reserve); err != nil {
				t.Fatal(err)
			}
			run := func(ctx context.Context) error {
				req, opts := cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}
				switch path {
				case "execute":
					_, err := m.Execute(ctx, []string{"claude"}, req, opts)
					return err
				case "count":
					_, err := m.ExecuteCount(ctx, []string{"claude"}, req, opts)
					return err
				default:
					stream, err := m.ExecuteStream(ctx, []string{"claude"}, req, opts)
					if err != nil {
						return err
					}
					for chunk := range stream.Chunks {
						if chunk.Err != nil {
							return chunk.Err
						}
					}
					return nil
				}
			}
			if err := run(context.Background()); err != ErrClaudeCodeOnly {
				t.Fatalf("non-native error=%v", err)
			}
			if calls := exec.executeCalls.Load() + exec.countCalls.Load() + exec.streamCalls.Load(); calls != 0 {
				t.Fatalf("non-native subscription calls=%d", calls)
			}
			c := &gin.Context{}
			MarkNativeClaudeCode(c)
			ctx := context.WithValue(context.Background(), "gin", c)
			if err := run(ctx); err != nil {
				t.Fatalf("native error=%v", err)
			}
		})
	}
}
