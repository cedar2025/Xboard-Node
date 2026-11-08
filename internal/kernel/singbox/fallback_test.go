package singbox

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
)

func TestLocalFallbackSurvivesPanelRefresh(t *testing.T) {
	kcfg := config.KernelConfig{Fallbacks: []config.FallbackConfig{
		{Dest: "127.0.0.1:8080"},
		{ALPN: "h2", Dest: "127.0.0.1:8082"},
	}}
	for _, port := range []int{443, 8443} {
		nc := testNodeSpec(&panel.NodeConfig{Protocol: "trojan", ServerPort: port, Network: "tcp", TLS: 1})
		cfg := buildConfig(kcfg, nc, testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
		inbound := cfg["inbounds"].([]M)[0]
		fallback := inbound["fallback"].(M)
		h2 := inbound["fallback_for_alpn"].(M)["h2"].(M)
		if fallback["server"] != "127.0.0.1" || fallback["server_port"] != 8080 || h2["server_port"] != 8082 {
			t.Fatalf("port %d: lost local fallback: %#v %#v", port, fallback, h2)
		}
		h1 := inbound["fallback_for_alpn"].(M)["http/1.1"].(M)
		alpn := inbound["tls"].(M)["alpn"].([]string)
		if h1["server_port"] != 8080 || len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
			t.Fatalf("port %d: wrong TLS ALPN: %#v %#v", port, h1, alpn)
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := singJSON.UnmarshalExtendedContext[option.Options](include.Context(context.Background()), data); err != nil {
			t.Fatalf("sing-box rejected fallback config: %v", err)
		}
	}
}
