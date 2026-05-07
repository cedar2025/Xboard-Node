package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func newTestServer(handler http.HandlerFunc) (*httptest.Server, *Client) {
	ts := httptest.NewServer(handler)
	client := NewClient(config.PanelConfig{
		URL:    ts.URL,
		Token:  "test-token",
		NodeID: 1,
	})
	return ts, client
}

func TestGetConfig_Success(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/config" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("token") != "test-token" {
			t.Errorf("missing token in query")
		}
		if r.URL.Query().Get("node_id") != "1" {
			t.Errorf("missing node_id in query")
		}
		w.Header().Set("ETag", `"etag-1"`)
		json.NewEncoder(w).Encode(NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 111,
			Cipher:     "aes-128-gcm",
		})
	})
	defer ts.Close()

	cfg, err := client.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Protocol != "shadowsocks" {
		t.Errorf("protocol: got %q", cfg.Protocol)
	}
	if cfg.ServerPort != 111 {
		t.Errorf("server_port: got %d", cfg.ServerPort)
	}
}

func TestGetConfig_NotModified(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("ETag", `"etag-1"`)
			json.NewEncoder(w).Encode(NodeConfig{Protocol: "shadowsocks"})
			return
		}
		if r.Header.Get("If-None-Match") != `"etag-1"` {
			t.Errorf("expected If-None-Match header, got %q", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	})
	defer ts.Close()

	// First call — get config
	cfg, err := client.GetConfig()
	if err != nil || cfg == nil {
		t.Fatalf("first GetConfig: err=%v cfg=%v", err, cfg)
	}

	// Second call — should be 304
	cfg, err = client.GetConfig()
	if err != nil {
		t.Fatalf("second GetConfig: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config for 304")
	}
}

func TestGetConfig_ServerError(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})
	defer ts.Close()

	_, err := client.GetConfig()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestGetUsers_Success(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("ETag", `"users-etag-1"`)
		json.NewEncoder(w).Encode(UsersResponse{
			Users: []User{
				{ID: 1, UUID: "uuid-1", SpeedLimit: 3, DeviceLimit: 2},
				{ID: 2, UUID: "uuid-2", SpeedLimit: 0, DeviceLimit: 0},
			},
		})
	})
	defer ts.Close()

	users, err := client.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("users count: got %d", len(users))
	}
	if users[0].UUID != "uuid-1" {
		t.Errorf("user[0].uuid: got %q", users[0].UUID)
	}
}

func TestGetUsers_NotModified(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("ETag", `"u-etag"`)
			json.NewEncoder(w).Encode(UsersResponse{Users: []User{{ID: 1, UUID: "u1"}}})
			return
		}
		w.WriteHeader(http.StatusNotModified)
	})
	defer ts.Close()

	users, _ := client.GetUsers()
	if len(users) != 1 {
		t.Fatalf("first call: got %d users", len(users))
	}
	users, err := client.GetUsers()
	if err != nil {
		t.Fatalf("second GetUsers: %v", err)
	}
	if users != nil {
		t.Error("expected nil for 304")
	}
}

func TestPushTraffic_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/server/UniProxy/push" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	data := map[int][2]int64{
		1: {1024, 2048},
		2: {512, 256},
	}
	if err := client.PushTraffic(data); err != nil {
		t.Fatalf("PushTraffic: %v", err)
	}
	if received == nil {
		t.Fatal("server received nil payload")
	}
	// Verify token was injected
	if received["token"] != "test-token" {
		t.Errorf("token: got %v", received["token"])
	}
}

func TestPushTraffic_Empty(t *testing.T) {
	called := false
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	if err := client.PushTraffic(nil); err != nil {
		t.Fatalf("PushTraffic nil: %v", err)
	}
	if called {
		t.Error("should not call server for empty traffic")
	}
}

func TestPushAlive_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/alive" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	data := map[int][]string{
		1: {"1.2.3.4", "5.6.7.8"},
	}
	if err := client.PushAlive(data); err != nil {
		t.Fatalf("PushAlive: %v", err)
	}
	if received == nil {
		t.Fatal("server received nil")
	}
}

func TestPushStatus_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	err := client.PushStatus(50.0, [2]uint64{8192, 4096}, [2]uint64{2048, 1024}, [2]uint64{100000, 50000})
	if err != nil {
		t.Fatalf("PushStatus: %v", err)
	}
	if received["cpu"].(float64) != 50.0 {
		t.Errorf("cpu: got %v", received["cpu"])
	}
}

func TestResetETags(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.Header().Set("ETag", `"e1"`)
			json.NewEncoder(w).Encode(NodeConfig{Protocol: "ss"})
			return
		}
		// After reset, should NOT send If-None-Match
		if r.Header.Get("If-None-Match") != "" {
			t.Errorf("expected no If-None-Match after reset, got %q", r.Header.Get("If-None-Match"))
		}
		json.NewEncoder(w).Encode(NodeConfig{Protocol: "ss"})
	})
	defer ts.Close()

	client.GetConfig()
	client.ResetETags()
	client.GetConfig()
}

func TestPushTraffic_ServerError(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("unavailable"))
	})
	defer ts.Close()

	data := map[int][2]int64{1: {100, 200}}
	err := client.PushTraffic(data)
	if err == nil {
		t.Fatal("expected error for 503")
	}
}

func TestClient_NodeTypeInQuery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node_type") != "hiddify" {
			t.Errorf("node_type: got %q, want hiddify", r.URL.Query().Get("node_type"))
		}
		json.NewEncoder(w).Encode(NodeConfig{Protocol: "hiddify"})
	}))
	defer ts.Close()

	client := NewClient(config.PanelConfig{
		URL:      ts.URL,
		Token:    "tok",
		NodeID:   1,
		NodeType: "hiddify",
	})
	client.GetConfig()
}

func TestStringOrArrayDecodeHook(t *testing.T) {
	// Test case: []interface{} -> StringOrArray
	input := map[string]interface{}{
		"padding_scheme": []interface{}{"stop=8", "0=30-30", "1=100-400"},
	}

	type TestConfig struct {
		PaddingScheme StringOrArray `json:"padding_scheme"`
	}

	var cfg TestConfig
	if err := decodeWeakRaw(input, &cfg); err != nil {
		t.Fatalf("decodeWeakRaw failed: %v", err)
	}

	want := "stop=8\n0=30-30\n1=100-400"
	if string(cfg.PaddingScheme) != want {
		t.Errorf("got %q, want %q", cfg.PaddingScheme, want)
	}
}

func TestStringOrArrayDecodeHook_String(t *testing.T) {
	// Test case: string -> StringOrArray
	input := map[string]interface{}{
		"padding_scheme": "stop=8\n0=30-30",
	}

	type TestConfig struct {
		PaddingScheme StringOrArray `json:"padding_scheme"`
	}

	var cfg TestConfig
	if err := decodeWeakRaw(input, &cfg); err != nil {
		t.Fatalf("decodeWeakRaw failed: %v", err)
	}

	want := "stop=8\n0=30-30"
	if string(cfg.PaddingScheme) != want {
		t.Errorf("got %q, want %q", cfg.PaddingScheme, want)
	}
}
