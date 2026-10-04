package executor

import (
	"bytes"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/tidwall/gjson"
	"testing"
)

func TestConfiguredClaudeCacheTTL(t *testing.T) {
	input := []byte(`{"cache_control":{"type":"ephemeral","ttl":"1h"},"tools":[{"name":"tool","cache_control":{"type":"ephemeral","ttl":"1h"}}],"system":[{"type":"text","text":"system","cache_control":{"type":"ephemeral","ttl":"1h"}}],"messages":[{"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`)
	for _, cfg := range []*config.Config{nil, {}} {
		if got := applyClaudeCacheTTL(input, cfg); !bytes.Equal(got, input) {
			t.Fatal("default changed native cache")
		}
	}
	cfg := &config.Config{}
	cfg.Client.Claude.CacheTTL = "5m"
	output := normalizeCacheControlTTL(applyClaudeCacheTTL(input, cfg))
	for _, path := range []string{"cache_control", "tools.0.cache_control", "system.0.cache_control", "messages.0.content.0.cache_control"} {
		if gjson.GetBytes(output, path+".ttl").Exists() {
			t.Fatalf("1h survived at %s", path)
		}
		if gjson.GetBytes(output, path+".type").String() != "ephemeral" {
			t.Fatalf("cache marker removed at %s", path)
		}
	}
	if gjson.GetBytes(output, "messages.0.content.0.text").String() != "hello" {
		t.Fatal("message changed")
	}
	parsed, err := config.ParseConfigBytes([]byte("config-version: 8\nclient:\n  claude:\n    cache-ttl: 5m\n"))
	if err != nil || parsed.Client.Claude.CacheTTL != "5m" {
		t.Fatalf("config parse: %v", err)
	}
}
