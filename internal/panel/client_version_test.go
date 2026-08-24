package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestReportMachineStatus_IncludesAgentVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/machine/status" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if v, ok := payload["agent_version"].(string); !ok || v == "" {
			t.Errorf("agent_version missing or empty in machine status payload: %#v", payload["agent_version"])
		}
		if payload["token"] != "tok" || payload["machine_id"].(float64) != 7 {
			t.Errorf("auth fields wrong: %#v", payload)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": true})
	}))
	defer ts.Close()

	client := NewClient(config.PanelConfig{
		URL:   ts.URL,
		Token: "tok",
	})
	client.machineID = 7

	if err := client.ReportMachineStatus(1.5,
		[2]uint64{100, 50}, [2]uint64{10, 5}, [2]uint64{1000, 500},
		1024.0, 2048.0,
	); err != nil {
		t.Fatalf("ReportMachineStatus: %v", err)
	}
}
