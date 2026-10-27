package tracker

import (
	"testing"
)

func TestProcess_InitialTraffic(t *testing.T) {
	tr := New()
	cumTraffic := map[int][2]int64{
		1: {100, 200},
		2: {50, 80},
	}
	aliveIPs := map[int]map[string]bool{
		1: {"1.1.1.1": true},
		2: {"2.2.2.2": true},
	}
	tr.Process(cumTraffic, aliveIPs, 2)

	flushed := tr.FlushTraffic()
	if flushed[1] != [2]int64{100, 200} {
		t.Errorf("user 1 traffic: got %v", flushed[1])
	}
	if flushed[2] != [2]int64{50, 80} {
		t.Errorf("user 2 traffic: got %v", flushed[2])
	}
}

func TestProcess_DeltaCalculation(t *testing.T) {
	tr := New()

	// First tick
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	// Second tick — counters advanced
	tr.Process(map[int][2]int64{1: {300, 500}}, nil, 1)

	flushed := tr.FlushTraffic()
	// Total: first tick 100/200 + delta 200/300 = 300/500
	if flushed[1] != [2]int64{300, 500} {
		t.Errorf("accumulated: got %v, want [300,500]", flushed[1])
	}
}

func TestProcess_CounterReset(t *testing.T) {
	tr := New()

	// First tick with high counters
	tr.Process(map[int][2]int64{1: {1000, 2000}}, nil, 1)
	tr.FlushTraffic() // clear accumulator

	// Counter reset (new value < old value) — treat as fresh
	tr.Process(map[int][2]int64{1: {50, 80}}, nil, 1)

	flushed := tr.FlushTraffic()
	if flushed[1] != [2]int64{50, 80} {
		t.Errorf("counter reset: got %v, want [50,80]", flushed[1])
	}
}

func TestProcess_UserDisappears(t *testing.T) {
	tr := New()

	// Tick 1: user present
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	// Tick 2: user gone
	tr.Process(map[int][2]int64{}, nil, 0)

	// Tick 3: user reappears — should count full bytes (treated as new)
	tr.Process(map[int][2]int64{1: {50, 30}}, nil, 1)

	flushed := tr.FlushTraffic()
	// First tick: 100/200, tick 2: 0, tick 3: 50/30 = total 150/230
	if flushed[1] != [2]int64{150, 230} {
		t.Errorf("after disappear: got %v, want [150,230]", flushed[1])
	}
}

func TestProcess_ZeroTraffic(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{}, nil, 0)

	if tr.HasTraffic() {
		t.Error("expected no traffic for empty input")
	}
}

func TestFlushTraffic(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{
		1: {100, 200},
		2: {50, 80},
	}, nil, 2)

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
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	flushed := tr.FlushTraffic()
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

	// Two ticks accumulate
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	tr.Process(map[int][2]int64{1: {200, 400}}, nil, 1)

	// Flush and restore
	first := tr.FlushTraffic()
	tr.RestoreTraffic(first)

	// Generate additional traffic
	tr.Process(map[int][2]int64{1: {250, 500}}, nil, 1)

	final := tr.FlushTraffic()
	// Restored: 200/400 (initial 100/200 + delta 100/200) + new delta 50/100 = 250/500
	if final[1][0] != 250 || final[1][1] != 500 {
		t.Errorf("additive restore: got %v", final[1])
	}
}

func TestAliveIPsReportsCurrentStateOnEveryCall(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{1: {100, 200}, 2: {30, 40}}, map[int]map[string]bool{
		1: {"1.1.1.1": true, "2.2.2.2": true},
		2: {"3.3.3.3": true},
	}, 3)

	// An unchanged device set must still be reported: the panel expires
	// device records it has not seen for five minutes.
	for i := 0; i < 2; i++ {
		alive := tr.AliveIPs()
		if len(alive[1]) != 2 || len(alive[2]) != 1 {
			t.Fatalf("call %d: AliveIPs() = %v", i, alive)
		}
	}
}

func TestAliveIPsSnapshotsAreIndependent(t *testing.T) {
	tr := New()
	tr.Process(nil, map[int]map[string]bool{1: {"1.1.1.1": true}}, 1)
	first := tr.AliveIPs()

	// A report goroutine may still be encoding first while the service takes
	// the next snapshot.
	tr.Process(nil, map[int]map[string]bool{2: {"2.2.2.2": true}}, 1)
	second := tr.AliveIPs()

	if len(first) != 1 || len(first[1]) != 1 || first[1][0] != "1.1.1.1" {
		t.Fatalf("first snapshot changed to %v", first)
	}
	if len(second) != 1 || len(second[2]) != 1 || second[2][0] != "2.2.2.2" {
		t.Fatalf("second snapshot = %v", second)
	}
}

func TestHasTraffic(t *testing.T) {
	tr := New()
	if tr.HasTraffic() {
		t.Error("new tracker should not have traffic")
	}

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
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

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	tr.FlushTraffic() // clear

	// Same values — no delta
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	if tr.HasTraffic() {
		t.Error("expected no traffic for zero delta")
	}
}

func TestTrafficAccumulation(t *testing.T) {
	tr := New()

	// Tick 1
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	// Tick 2 (cumulative 300, 500 → delta 200, 300)
	tr.Process(map[int][2]int64{1: {300, 500}}, nil, 1)
	// Tick 3 (cumulative 350, 600 → delta 50, 100)
	tr.Process(map[int][2]int64{1: {350, 600}}, nil, 1)

	flushed := tr.FlushTraffic()
	// Total: 100+200+50 = 350 upload, 200+300+100 = 600 download
	if flushed[1] != [2]int64{350, 600} {
		t.Errorf("accumulated: got %v, want [350,600]", flushed[1])
	}
}
