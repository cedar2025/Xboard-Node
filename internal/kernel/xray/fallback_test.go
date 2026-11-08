package xray

import (
	"bytes"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/xtls/xray-core/infra/conf/serial"
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
		fallbacks := inbound["settings"].(M)["fallbacks"].([]M)
		if len(fallbacks) != 2 || fallbacks[0]["dest"] != "127.0.0.1:8080" || fallbacks[1]["alpn"] != "h2" {
			t.Fatalf("port %d: lost local fallback: %#v", port, fallbacks)
		}
		alpn := inbound["streamSettings"].(M)["tlsSettings"].(M)["alpn"].([]string)
		if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
			t.Fatalf("port %d: wrong TLS ALPN: %#v", port, alpn)
		}
		data, err := marshalConfig(kcfg, nc, testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
			t.Fatalf("xray rejected fallback config: %v", err)
		}
	}
}

func TestTrojanTLSAutodetectDoesNotMutatePanelSpec(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{Protocol: "trojan", ServerPort: 443, Network: "tcp"})
	_ = buildConfig(testKernelCfg, nc, testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if nc.TLS != 0 {
		t.Fatalf("buildConfig changed panel TLS state to %d", nc.TLS)
	}
}
