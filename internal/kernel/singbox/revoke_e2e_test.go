//go:build with_quic

package singbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A Hysteria2 client authenticates once per QUIC connection and then opens a
// stream per proxied request. Removing the user from the inbound only blocks
// new handshakes, so a removed user (traffic exhausted, expired, banned) must
// also lose the streams they already have and any new stream on the old
// session. Otherwise they keep using the node, uncounted and unlimited.
func TestHysteria2RemovedUserLosesAuthenticatedSession(t *testing.T) {
	echoAddr := startEchoServer(t)
	certPEM, keyPEM := selfSignedCert(t)
	port := freeUDPPort(t)

	k := New(config.KernelConfig{
		Type: "singbox",
		// Let the test reach its loopback echo server; production routing
		// blocks private ranges.
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
	})
	nc := &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: port}
	users := []model.UserSpec{
		{ID: 1, UUID: "11111111-1111-1111-1111-111111111111"},
		{ID: 2, UUID: "22222222-2222-2222-2222-222222222222"},
	}
	if err := k.Start(nc, users, kernel.TLSCert{CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(k.Stop)

	removedClient := newHysteria2Client(t, port, users[0].UUID)
	existing := dialEcho(t, removedClient, echoAddr)
	keptClient := newHysteria2Client(t, port, users[1].UUID)
	keptExisting := dialEcho(t, keptClient, echoAddr)

	if _, err := k.RemoveUsers([]model.UserSpec{{ID: 1}}); err != nil {
		t.Fatalf("RemoveUsers() error = %v", err)
	}

	if echoes(existing) {
		t.Error("removed user's existing stream still relays traffic")
	}
	if conn, err := removedClient.DialConn(context.Background(), singM.ParseSocksaddr(echoAddr)); err == nil {
		defer conn.Close()
		if echoes(conn) {
			t.Error("removed user opened a new stream on the authenticated session")
		}
	}

	if !echoes(keptExisting) {
		t.Error("remaining user's existing stream was disrupted")
	}
	dialEcho(t, keptClient, echoAddr)
}

func newHysteria2Client(t *testing.T, port int, password string) *hysteria2.Client {
	t.Helper()
	ctx := context.Background()
	tlsConfig, err := sbtls.NewClient(ctx, nil, "127.0.0.1", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "localhost",
		Insecure:   true,
	})
	if err != nil {
		t.Fatalf("tls.NewClient() error = %v", err)
	}
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:       ctx,
		Dialer:        N.SystemDialer,
		Logger:        logger.NOP(),
		ServerAddress: singM.ParseSocksaddrHostPort("127.0.0.1", uint16(port)),
		Password:      password,
		TLSConfig:     tlsConfig,
	})
	if err != nil {
		t.Fatalf("hysteria2.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(errors.New("test done")) })
	return client
}

// dialEcho opens a stream through the client and requires it to relay.
func dialEcho(t *testing.T, client *hysteria2.Client, echoAddr string) net.Conn {
	t.Helper()
	conn, err := client.DialConn(context.Background(), singM.ParseSocksaddr(echoAddr))
	if err != nil {
		t.Fatalf("DialConn() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if !echoes(conn) {
		t.Fatal("stream did not relay traffic before removal")
	}
	return conn
}

// echoes reports whether a round trip through conn reaches the echo server.
func echoes(conn net.Conn) bool {
	payload := []byte("ping")
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return bytes.Equal(buf, payload)
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func selfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
