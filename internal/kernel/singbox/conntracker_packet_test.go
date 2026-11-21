package singbox

import (
	"testing"

	N "github.com/sagernet/sing/common/network"
)

func TestPacketCopyCountersSurviveUnwrap(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"first": 1, "second": 2})
	// The copy loop obtains the callbacks before moving packets on the underlying
	// connection. Drive those same callbacks with asymmetric byte counts.
	base := new(struct{ N.PacketConn })
	for _, tc := range []struct {
		name             string
		upload, download int64
	}{{"first", 7, 19}, {"second", 13, 5}} {
		conn := tracker.RoutedPacketConnection(t.Context(), base, testInboundContext(tc.name, "127.0.0.1"), nil, nil)
		reader, reads := N.UnwrapCountPacketReader(conn, nil)
		writer, writes := N.UnwrapCountPacketWriter(conn, nil)
		if reader != base || writer != base || len(reads) != 1 || len(writes) != 1 {
			t.Fatalf("%s: want underlying packet connection and one counter per direction, got %d read, %d write", tc.name, len(reads), len(writes))
		}
		reads[0](tc.upload)
		writes[0](tc.download)
	}
	tracker.SetUserMap(map[string]int{"second": 2})
	traffic, _, _ := tracker.GetUserTraffic()
	if got := traffic[1]; got != [2]int64{7, 19} {
		t.Errorf("first account traffic = %v, want [7 19]", got)
	}
	if got := traffic[2]; got != [2]int64{13, 5} {
		t.Errorf("second account traffic = %v, want [13 5]", got)
	}
}
