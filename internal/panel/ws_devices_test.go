package panel

import (
	"reflect"
	"testing"
)

func decodeDevicesEvent(t *testing.T, data string) WSEvent {
	t.Helper()
	var got []WSEvent
	ws := NewWSClient("ws://unused", "token", 1, WSClientConfig{}, func(e WSEvent) { got = append(got, e) }, nil, func() map[string]interface{} { return nil })
	ws.handleDataEvent(wsMessage{Event: WSEventSyncDevices, Data: []byte(data)})
	if len(got) != 1 {
		t.Fatalf("sync.devices %s was dropped", data)
	}
	return got[0]
}

// The panel builds each user's IP list with PHP array_unique, which keeps the
// original keys: a duplicate IP ahead of another IP turns the list into a JSON
// object. One such user must not cost the node every user's device state.
func TestSyncDevicesAcceptsIPListsEncodedAsObjects(t *testing.T) {
	event := decodeDevicesEvent(t, `{"node_id":485,"users":{"2765":{"0":"179.1.1.1","1":"69.2.2.2","3":"179.3.3.3"},"8":["10.0.0.1"]}}`)

	want := map[int][]string{2765: {"179.1.1.1", "69.2.2.2", "179.3.3.3"}, 8: {"10.0.0.1"}}
	if !reflect.DeepEqual(event.DeviceUsers, want) {
		t.Fatalf("DeviceUsers = %v, want %v", event.DeviceUsers, want)
	}
	if event.NodeID != 485 {
		t.Fatalf("NodeID = %d, want 485", event.NodeID)
	}
}

// json_encode of an empty PHP array is [], meaning none of the node's users
// has a device anywhere; the node must replace its stale global state.
func TestSyncDevicesAcceptsEmptyUserList(t *testing.T) {
	event := decodeDevicesEvent(t, `{"node_id":485,"users":[]}`)

	if event.DeviceUsers == nil || len(event.DeviceUsers) != 0 {
		t.Fatalf("DeviceUsers = %#v, want empty non-nil map", event.DeviceUsers)
	}
}
