package config

import "testing"

func TestExampleConfigLoads(t *testing.T) {
	t.Setenv("BIMA_TELEGRAM_TOKEN", "x")
	t.Setenv("BIMA_TELEGRAM_CHAT_ID", "1")
	t.Setenv("BIMA_DISCORD_WEBHOOK", "http://x")
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDetect || len(c.Ban.RuntimeAPIs) != 1 || !c.CRS.FastPath || c.State.Backend != "memory" {
		t.Fatalf("unexpected: %+v", c)
	}
	for _, f := range []string{"../../deploy/e2e/config.yaml", "../../deploy/e2e/config.untuned.yaml", "../../deploy/e2e-prod/config.yaml"} {
		if _, err := Load(f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}
