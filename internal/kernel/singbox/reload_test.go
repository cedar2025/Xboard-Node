package singbox

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func reloadTestPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func accepts(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

var reloadUsers = []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}

// A protocol switch on the same box must close the previous inbound: after
// the reload only the new tag exists and only the new port accepts.
func TestReloadProtocolSwitchRemovesStaleInbound(t *testing.T) {
	k := New(config.KernelConfig{Type: "singbox", LogLevel: "error"})
	t.Cleanup(k.Stop)
	oldPort := reloadTestPort(t)
	newPort := reloadTestPort(t)

	vless := &model.NodeSpec{Protocol: "vless", ServerPort: oldPort, Network: "tcp"}
	if err := k.Start(vless, reloadUsers, kernel.TLSCert{}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !accepts(fmt.Sprintf("127.0.0.1:%d", oldPort)) {
		t.Fatal("vless listener not accepting")
	}

	ss := &model.NodeSpec{Protocol: "shadowsocks", ServerPort: newPort, Cipher: "aes-128-gcm"}
	if err := k.Reload(ss, reloadUsers, kernel.TLSCert{}); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if accepts(fmt.Sprintf("127.0.0.1:%d", oldPort)) {
		t.Fatal("old vless listener survived the protocol switch")
	}
	if !accepts(fmt.Sprintf("127.0.0.1:%d", newPort)) {
		t.Fatal("new shadowsocks listener not accepting")
	}
	tags := inboundTags(k)
	if len(tags) != 1 || tags[0] != "shadowsocks-in" {
		t.Fatalf("inbound tags after switch = %v", tags)
	}
}

// When the new inbound cannot bind, the previous inbound is restored with the
// latest user set so the node keeps serving while the service retries.
func TestReloadFailureRestoresPreviousInbound(t *testing.T) {
	k := New(config.KernelConfig{Type: "singbox", LogLevel: "error"})
	t.Cleanup(k.Stop)
	oldPort := reloadTestPort(t)
	busyPort := reloadTestPort(t)
	// Hold the wildcard address: the kernel listens on "::", and only a
	// listener on the same wildcard reliably conflicts on every platform.
	holder, err := net.Listen("tcp", fmt.Sprintf(":%d", busyPort))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	vless := &model.NodeSpec{Protocol: "vless", ServerPort: oldPort, Network: "tcp", ListenIP: "127.0.0.1"}
	if err := k.Start(vless, reloadUsers, kernel.TLSCert{}); err != nil {
		t.Fatalf("start: %v", err)
	}

	latest := []model.UserSpec{{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888"}}
	ss := &model.NodeSpec{Protocol: "shadowsocks", ServerPort: busyPort, Cipher: "aes-128-gcm", ListenIP: "127.0.0.1"}
	if err := k.Reload(ss, latest, kernel.TLSCert{}); err == nil {
		t.Fatal("reload onto a busy port must fail")
	}
	if !k.IsRunning() {
		t.Fatal("kernel must stay running")
	}
	if !accepts(fmt.Sprintf("127.0.0.1:%d", oldPort)) {
		t.Fatal("previous vless listener was not restored")
	}
	tags := inboundTags(k)
	if len(tags) != 1 || tags[0] != "vless-in" {
		t.Fatalf("inbound tags after rollback = %v", tags)
	}
	// The kernel's bookkeeping still describes the running (old) config.
	k.mu.RLock()
	proto := k.nodeConfig.Protocol
	k.mu.RUnlock()
	if proto != "vless" {
		t.Fatalf("nodeConfig after rollback = %s", proto)
	}

	// Once the port is free the same reload succeeds.
	holder.Close()
	if err := k.Reload(ss, latest, kernel.TLSCert{}); err != nil {
		t.Fatalf("reload after port freed: %v", err)
	}
	if accepts(fmt.Sprintf("127.0.0.1:%d", oldPort)) || !accepts(fmt.Sprintf("127.0.0.1:%d", busyPort)) {
		t.Fatal("listeners did not move to the new target")
	}
}

// Validate must reject what Start would reject, without binding anything.
func TestValidateRejectsMissingTLSForQUICProtocols(t *testing.T) {
	k := New(config.KernelConfig{Type: "singbox", LogLevel: "error"})
	err := k.Validate(&model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: 1}, reloadUsers, kernel.TLSCert{})
	if err == nil {
		t.Fatal("hysteria2 without certificate material must not validate")
	}
	if err := k.Validate(&model.NodeSpec{Protocol: "shadowsocks", Cipher: "aes-128-gcm", ServerPort: 1}, reloadUsers, kernel.TLSCert{}); err != nil {
		t.Fatalf("shadowsocks must validate: %v", err)
	}
	if k.IsRunning() {
		t.Fatal("Validate must not start anything")
	}
}

func TestValidateRejectsUnknownProtocol(t *testing.T) {
	k := New(config.KernelConfig{Type: "singbox", LogLevel: "error"})
	if err := k.Validate(&model.NodeSpec{Protocol: "wireguard", ServerPort: 1}, reloadUsers, kernel.TLSCert{}); err == nil {
		t.Fatal("unknown protocol must not validate")
	}
}

// inboundTags lists the tags currently registered on the running box.
func inboundTags(k *SingBox) []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.ctx == nil {
		return nil
	}
	im := serviceInboundManager(k)
	if im == nil {
		return nil
	}
	var tags []string
	for _, inb := range im.Inbounds() {
		tags = append(tags, inb.Tag())
	}
	return tags
}
