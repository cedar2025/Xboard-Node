package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestBootstrapRefetchesUsersAfterInvalidInitialConfiguration(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	var configs, notModifiedUsers atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/server/handshake", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"websocket": map[string]any{"enabled": false}})
	})
	mux.HandleFunc("/api/v2/server/config", func(w http.ResponseWriter, r *http.Request) {
		configuredPort := port
		if configs.Add(1) == 1 {
			configuredPort = 0
		}
		w.Header().Set("ETag", fmt.Sprintf("config-%d", configuredPort))
		json.NewEncoder(w).Encode(map[string]any{"protocol": "vless", "network": "tcp", "server_port": configuredPort})
	})
	mux.HandleFunc("/api/v2/server/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == "users-v1" {
			notModifiedUsers.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", "users-v1")
		json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{"id": 1, "uuid": "aaaaaaaa-1111-2222-3333-444444444444"}}})
	})
	mux.HandleFunc("/api/v2/server/report", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) })
	server := httptest.NewServer(mux)
	defer server.Close()
	cfg := testConfig(t)
	cfg.Panel.URL = server.URL
	cfg.Panel.MachineID = 11
	cp := controlplane.NewMachinePanelControlPlane(panel.NewClient(cfg.Panel), cfg.Kernel, nil, nil)
	s := NewWithControlPlane(cfg, cp)
	s.retryDelayFn = func(int) time.Duration { return 10 * time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("service did not stop")
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("initial retry never started listener; configs=%d user304=%d", configs.Load(), notModifiedUsers.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if configs.Load() < 2 || notModifiedUsers.Load() != 0 {
		t.Fatalf("incomplete bootstrap snapshots: configs=%d user304=%d", configs.Load(), notModifiedUsers.Load())
	}
}
