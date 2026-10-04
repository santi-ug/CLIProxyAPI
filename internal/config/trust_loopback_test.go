package config

import "testing"

func TestParseConfigBytesTrustLoopback(t *testing.T) {
	for name, payload := range map[string]string{
		"legacy top-level": "trust-loopback: true\n",
		"v8 server block":  "config-version: 8\nserver:\n  trust-loopback: true\n",
	} {
		cfg, errParse := ParseConfigBytes([]byte(payload))
		if errParse != nil {
			t.Fatalf("%s: ParseConfigBytes() error = %v", name, errParse)
		}
		if !cfg.TrustLoopback {
			t.Errorf("%s: TrustLoopback = false, want true", name)
		}
	}

	cfg, errParse := ParseConfigBytes([]byte("port: 8317\n"))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if cfg.TrustLoopback {
		t.Error("TrustLoopback must default to false")
	}
}
