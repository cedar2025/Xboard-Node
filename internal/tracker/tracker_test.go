package tracker

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/kernel"
)

func TestProcess_InitialTraffic(t *testing.T) {
	tr := New()
	conns := []kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200, SourceIP: "1.1.1.1"},
		{ID: "c2", UserID: 2, Upload: 50, Download: 80, SourceIP: "2.2.2.2"},
	}

	interval := tr.Process(conns)

	if interval[1] != [2]int64{100, 200} {
		t.Errorf("user 1 interval: got %v", interval[1])
	}
	if interval[2] != [2]int64{50, 80} {
		t.Errorf("user 2 interval: got %v", interval[2])
	}
}

func TestProcess_DeltaCalculation(t *testing.T) {
	tr := New()

	// First tick
	conns := []kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
	}
	tr.Process(conns)

	// Second tick — counters advanced
	conns[0].Upload = 300
	conns[0].Download = 500
	interval := tr.Process(conns)

	if interval[1] != [2]int64{200, 300} {
		t.Errorf("delta: got %v, want [200,300]", interval[1])
	}
}

func TestProcess_CounterReset(t *testing.T) {
	tr := New()

	// First tick with high counters
	conns := []kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 1000, Download: 2000},
	}
	tr.Process(conns)

	// Counter reset (new value < old value) — treat as fresh
	conns[0].Upload = 50
	conns[0].Download = 80
	interval := tr.Process(conns)

	if interval[1] != [2]int64{50, 80} {
		t.Errorf("counter reset: got %v, want [50,80]", interval[1])
	}
}

func TestProcess_ConnectionCleanup(t *testing.T) {
	tr := New()

	// Tick 1: connection exists
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
	})

	// Tick 2: connection gone — should clean up state
	tr.Process([]kernel.Connection{})

	// Tick 3: same conn ID reappears — should count full bytes (not delta)
	interval := tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 50, Download: 30},
	})

	if interval[1] != [2]int64{50, 30} {
		t.Errorf("after cleanup: got %v, want [50,30]", interval[1])
	}
}

func TestProcess_ZeroUserID(t *testing.T) {
	tr := New()
	interval := tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 0, Upload: 100, Download: 200},
	})

	if len(interval) != 0 {
		t.Errorf("expected no interval traffic for userID=0, got %v", interval)
	}
}

func TestProcess_MultipleConnectionsSameUser(t *testing.T) {
	tr := New()
	conns := []kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
		{ID: "c2", UserID: 1, Upload: 50, Download: 80},
	}

	interval := tr.Process(conns)

	if interval[1] != [2]int64{150, 280} {
		t.Errorf("aggregated: got %v, want [150,280]", interval[1])
	}
}

func TestFlushTraffic(t *testing.T) {
	tr := New()
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
		{ID: "c2", UserID: 2, Upload: 50, Download: 80},
	})

	flushed := tr.FlushTraffic()
	if flushed[1] != [2]int64{100, 200} {
		t.Errorf("flushed user 1: got %v", flushed[1])
	}
	if flushed[2] != [2]int64{50, 80} {
		t.Errorf("flushed user 2: got %v", flushed[2])
	}

	// After flush, should be empty
	if tr.HasTraffic() {
		t.Error("expected no traffic after flush")
	}
	flushed2 := tr.FlushTraffic()
	if len(flushed2) != 0 {
		t.Errorf("expected empty after second flush, got %v", flushed2)
	}
}

func TestRestoreTraffic(t *testing.T) {
	tr := New()

	// Generate some traffic
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
	})

	flushed := tr.FlushTraffic()

	// Restore (simulating failed push)
	tr.RestoreTraffic(flushed)

	if !tr.HasTraffic() {
		t.Error("expected traffic after restore")
	}

	restored := tr.FlushTraffic()
	if restored[1] != [2]int64{100, 200} {
		t.Errorf("restored: got %v", restored[1])
	}
}

func TestRestoreTraffic_Additive(t *testing.T) {
	tr := New()

	// Generate traffic
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
	})

	// Generate more traffic
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 200, Download: 400},
	})

	// Flush and restore
	first := tr.FlushTraffic()
	tr.RestoreTraffic(first)

	// Generate additional traffic
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 250, Download: 500},
	})

	final := tr.FlushTraffic()
	// Should be restored(200,400) + delta(50,100) = (250,500)
	if final[1][0] != 250 || final[1][1] != 500 {
		t.Errorf("additive restore: got %v", final[1])
	}
}

func TestFlushAliveIPs(t *testing.T) {
	tr := New()
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200, SourceIP: "1.1.1.1"},
		{ID: "c2", UserID: 1, Upload: 50, Download: 80, SourceIP: "2.2.2.2"},
		{ID: "c3", UserID: 2, Upload: 30, Download: 40, SourceIP: "3.3.3.3"},
	})

	aliveIPs := tr.FlushAliveIPs()
	if len(aliveIPs[1]) != 2 {
		t.Errorf("user 1 IPs: got %d, want 2", len(aliveIPs[1]))
	}
	if len(aliveIPs[2]) != 1 {
		t.Errorf("user 2 IPs: got %d, want 1", len(aliveIPs[2]))
	}

	// After flush, should be empty
	aliveIPs2 := tr.FlushAliveIPs()
	if len(aliveIPs2) != 0 {
		t.Errorf("expected empty after second flush, got %v", aliveIPs2)
	}
}

func TestFlushAliveIPs_DedupSameIP(t *testing.T) {
	tr := New()
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200, SourceIP: "1.1.1.1"},
		{ID: "c2", UserID: 1, Upload: 50, Download: 80, SourceIP: "1.1.1.1"},
	})

	aliveIPs := tr.FlushAliveIPs()
	if len(aliveIPs[1]) != 1 {
		t.Errorf("expected dedup to 1 IP, got %d", len(aliveIPs[1]))
	}
}

func TestHasTraffic(t *testing.T) {
	tr := New()
	if tr.HasTraffic() {
		t.Error("new tracker should not have traffic")
	}

	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
	})
	if !tr.HasTraffic() {
		t.Error("should have traffic after process")
	}

	tr.FlushTraffic()
	if tr.HasTraffic() {
		t.Error("should not have traffic after flush")
	}
}

func TestProcess_NoTrafficDelta(t *testing.T) {
	tr := New()

	conns := []kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
	}
	tr.Process(conns)

	// Same values — no delta
	interval := tr.Process(conns)
	if len(interval) != 0 {
		t.Errorf("expected no interval traffic for zero delta, got %v", interval)
	}
}

func TestOnlineCountsUniqueIPs(t *testing.T) {
	tr := New()
	// 1 user, 3 connections from 2 unique IPs → online should be 2 (not 3)
	conns := []kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200, SourceIP: "1.1.1.1"},
		{ID: "c2", UserID: 1, Upload: 50, Download: 80, SourceIP: "1.1.1.1"},
		{ID: "c3", UserID: 1, Upload: 30, Download: 40, SourceIP: "2.2.2.2"},
	}
	tr.Process(conns)

	online := tr.CurrentOnline()
	if online[1] != 2 {
		t.Errorf("online should count unique IPs: got %d, want 2", online[1])
	}
}

func TestFlushOnline(t *testing.T) {
	tr := New()
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200, SourceIP: "1.1.1.1"},
		{ID: "c2", UserID: 1, Upload: 50, Download: 80, SourceIP: "2.2.2.2"},
		{ID: "c3", UserID: 2, Upload: 30, Download: 40, SourceIP: "3.3.3.3"},
	})

	flushed := tr.FlushOnline()
	if flushed[1] != 2 {
		t.Errorf("user 1 online: got %d, want 2", flushed[1])
	}
	if flushed[2] != 1 {
		t.Errorf("user 2 online: got %d, want 1", flushed[2])
	}

	// After flush, should be empty
	flushed2 := tr.FlushOnline()
	if len(flushed2) != 0 {
		t.Errorf("expected empty after second flush, got %v", flushed2)
	}
}

func TestRestoreOnline(t *testing.T) {
	tr := New()
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200, SourceIP: "1.1.1.1"},
	})

	flushed := tr.FlushOnline()
	tr.RestoreOnline(flushed)

	restored := tr.FlushOnline()
	if restored[1] != 1 {
		t.Errorf("restored online: got %d, want 1", restored[1])
	}
}

func TestTrafficAccumulation(t *testing.T) {
	tr := New()

	// Tick 1
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 100, Download: 200},
	})
	// Tick 2
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 300, Download: 500},
	})
	// Tick 3
	tr.Process([]kernel.Connection{
		{ID: "c1", UserID: 1, Upload: 350, Download: 600},
	})

	flushed := tr.FlushTraffic()
	// Total: 100+200+50 = 350 upload, 200+300+100 = 600 download
	if flushed[1] != [2]int64{350, 600} {
		t.Errorf("accumulated: got %v, want [350,600]", flushed[1])
	}
}
