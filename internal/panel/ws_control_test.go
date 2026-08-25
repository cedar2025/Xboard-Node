package panel

import (
	"encoding/json"
	"testing"
	"time"
)

// Control channel events (control.reload / control.restart) must be delivered
// to the onEvent callback with correct type and node_id, so the panel can
// remotely reload or restart nodes/machines.
func TestWSEventParse_ControlEvents(t *testing.T) {
	cases := []struct {
		name     string
		payload  map[string]interface{}
		wantType string
		wantNode int
	}{
		{
			name:     "node-level reload",
			payload:  map[string]interface{}{"node_id": 6},
			wantType: WSEventControlReload,
			wantNode: 6,
		},
		{
			name:     "machine-level restart (no node_id)",
			payload:  map[string]interface{}{},
			wantType: WSEventControlRestart,
			wantNode: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan WSEvent, 1)
			w := NewWSClient("ws://unused", "tok", 0,
				WSClientConfig{StatusInterval: time.Second},
				func(ev WSEvent) { got <- ev }, nil, nil)

			data, _ := json.Marshal(tc.payload)
			w.handleDataEvent(wsMessage{Event: tc.wantType, Data: data})

			select {
			case ev := <-got:
				if ev.Type != tc.wantType {
					t.Errorf("type = %q, want %q", ev.Type, tc.wantType)
				}
				if ev.NodeID != tc.wantNode {
					t.Errorf("node_id = %d, want %d", ev.NodeID, tc.wantNode)
				}
			default:
				t.Fatal("onEvent not called for control event")
			}
		})
	}
}
