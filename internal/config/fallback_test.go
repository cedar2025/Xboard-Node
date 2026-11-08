package config

import "testing"

func TestLocalFallbacksInheritAndValidate(t *testing.T) {
	path := writeTemp(t, `
kernel:
  type: xray
  fallbacks:
    - dest: "127.0.0.1:8080"
    - alpn: h2
      dest: "127.0.0.1:8082"
instances:
  - panel:
      url: https://panel.example.com
      token: secret
      node_id: 1
`)
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := root.Instances[0].Kernel.Fallbacks; len(got) != 2 || got[1].ALPN != "h2" || got[1].Dest != "127.0.0.1:8082" {
		t.Fatalf("inherited fallbacks: %#v", got)
	}
	for _, bad := range [][]FallbackConfig{
		{{Dest: "8080"}},
		{{Dest: "127.0.0.1:0"}},
		{{ALPN: "h2", Dest: "127.0.0.1:8080"}, {ALPN: "h2", Dest: "127.0.0.1:8082"}},
	} {
		if err := validateFallbacks(bad); err == nil {
			t.Errorf("accepted invalid fallback: %#v", bad)
		}
	}
}
