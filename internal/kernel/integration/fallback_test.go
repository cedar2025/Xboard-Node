//go:build integration

package integration_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox"
	"github.com/cedar2025/xboard-node/internal/kernel/xray"
	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func testCertificate(t *testing.T) (kernel.TLSCert, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return kernel.TLSCert{CertPEM: certPEM, KeyPEM: keyPEM}, pool
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func TestTrojanTLSFallbackHTTP11AndH2(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fallback-ok"))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)
	h2Backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fallback-h2-ok"))
	}), &http2.Server{}))
	defer h2Backend.Close()
	h2URL, _ := url.Parse(h2Backend.URL)
	cert, roots := testCertificate(t)

	for _, name := range []string{"xray", "singbox"} {
		t.Run(name, func(t *testing.T) {
			kcfg := config.KernelConfig{
				Type:      name,
				ConfigDir: filepath.Join(t.TempDir(), "config"),
				Fallbacks: []config.FallbackConfig{
					{Dest: backendURL.Host},
					{ALPN: "h2", Dest: h2URL.Host},
				},
			}
			var node kernel.Kernel
			if name == "xray" {
				node = xray.New(kcfg)
			} else {
				node = singbox.New(kcfg)
			}
			port := freePort(t)
			spec := &model.NodeSpec{Protocol: "trojan", Network: "tcp", ListenIP: "127.0.0.1", ServerPort: port, TLS: 1}
			spec.CustomRouteRules = []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.1"}}, Action: model.RouteAction{Type: "direct"}}}
			if err := node.Start(spec, []model.UserSpec{{ID: 1, UUID: "valid-password"}}, cert); err != nil {
				t.Fatal(err)
			}
			defer node.Stop()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{
				RootCAs: roots, ServerName: "localhost", NextProtos: []string{"http/1.1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("fallback status: %s", response.Status)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "fallback-ok" {
				t.Fatalf("fallback body = %q, error = %v", body, err)
			}

			h2Client := &http.Client{Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{
						RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h2"},
					})
				},
			}}
			h2Response, err := h2Client.Get("http://localhost/")
			if err != nil {
				t.Fatal(err)
			}
			defer h2Response.Body.Close()
			h2Body, err := io.ReadAll(h2Response.Body)
			if err != nil || h2Response.StatusCode != http.StatusOK || string(h2Body) != "fallback-h2-ok" {
				t.Fatalf("h2 fallback status=%s body=%q error=%v", h2Response.Status, h2Body, err)
			}

			validConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{
				RootCAs: roots, ServerName: "localhost",
			})
			if err != nil {
				t.Fatal(err)
			}
			defer validConn.Close()
			validConn.SetDeadline(time.Now().Add(5 * time.Second))
			_, backendPortText, _ := net.SplitHostPort(backendURL.Host)
			backendPort, _ := strconv.Atoi(backendPortText)
			digest := sha256.Sum224([]byte("valid-password"))
			request := append([]byte(hex.EncodeToString(digest[:])+"\r\n"), 1, 1, 127, 0, 0, 1, byte(backendPort>>8), byte(backendPort))
			request = append(request, []byte("\r\nGET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")...)
			if _, err := validConn.Write(request); err != nil {
				t.Fatal(err)
			}
			validResponse, err := http.ReadResponse(bufio.NewReader(validConn), nil)
			if err != nil {
				t.Fatalf("valid Trojan connection failed: %v", err)
			}
			defer validResponse.Body.Close()
			validBody, err := io.ReadAll(validResponse.Body)
			if err != nil || validResponse.StatusCode != http.StatusOK || string(validBody) != "fallback-ok" {
				t.Fatalf("valid Trojan status=%s body=%q error=%v", validResponse.Status, validBody, err)
			}
		})
	}
}
