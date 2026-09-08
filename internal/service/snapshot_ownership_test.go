package service

import (
	"context"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

// Ownership of the configuration snapshots. The desired snapshot, the prepared
// snapshot and the applied snapshot must each be owned by the service and be
// described by their own hash, whatever the caller does with the object it
// handed over. These tests mutate the caller's object sequentially after the
// hand-over; they do not model concurrent writers.

// ownedSpec is a target with every nested field a snapshot must own: maps
// with nested maps, slices of structs holding slices, and pointers.
func ownedSpec(port int) *model.NodeSpec {
	return &model.NodeSpec{
		Protocol: "vless", ServerPort: port, Network: "ws", TLS: 1, ServerName: "edge.example.test",
		NetworkSettings:  map[string]any{"path": "/ws", "headers": map[string]any{"Host": "edge.example.test"}},
		TLSSettings:      map[string]any{"server_name": "edge.example.test"},
		Routes:           []model.RouteRule{{ID: 1, Match: []string{"geosite:cn"}, Action: "block"}},
		CustomRouteRules: []model.CustomRouteRule{{Name: "lan", Match: model.RouteMatch{IPCIDRs: []string{"10.0.0.0/8"}}, Action: model.RouteAction{Type: "direct"}}},
		CertConfig:       &config.CertConfig{CertMode: "self"},
		Multiplex:        &model.MultiplexConfig{Enabled: true, MaxStreams: 4},
	}
}

// scramble mutates every level of spec in place, the way a caller that keeps
// reusing its own object would.
func scramble(spec *model.NodeSpec) {
	spec.ServerPort++
	spec.NetworkSettings["path"] = "/changed"
	spec.NetworkSettings["headers"].(map[string]any)["Host"] = "changed.example.test"
	spec.TLSSettings["server_name"] = "changed.example.test"
	spec.Routes[0].Match[0] = "geosite:changed"
	spec.CustomRouteRules[0].Match.IPCIDRs[0] = "192.0.2.0/24"
	spec.CertConfig.CertMode = "none"
	spec.Multiplex.MaxStreams = 99
}

func assertUnscrambled(t *testing.T, name string, spec *model.NodeSpec, port int) {
	t.Helper()
	if spec.ServerPort != port ||
		spec.NetworkSettings["path"] != "/ws" ||
		spec.NetworkSettings["headers"].(map[string]any)["Host"] != "edge.example.test" ||
		spec.TLSSettings["server_name"] != "edge.example.test" ||
		spec.Routes[0].Match[0] != "geosite:cn" ||
		spec.CustomRouteRules[0].Match.IPCIDRs[0] != "10.0.0.0/8" ||
		spec.CertConfig.CertMode != "self" ||
		spec.Multiplex.MaxStreams != 4 {
		t.Fatalf("caller mutation leaked into the %s snapshot: %+v", name, spec)
	}
}

func TestDesiredSnapshotIsOwnedByTheServiceOnEveryPath(t *testing.T) {
	users := []model.UserSpec{userA}
	paths := map[string]func(t *testing.T, s *Service, spec *model.NodeSpec){
		"bootstrap": func(t *testing.T, s *Service, spec *model.NodeSpec) {
			s.source.(*fakeSource).bootstrap = controlplane.Bootstrap{Config: spec, Users: users}
			if err := s.initialSetup(context.Background()); err != nil {
				t.Fatal(err)
			}
		},
		"ws": func(t *testing.T, s *Service, spec *model.NodeSpec) {
			s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: spec, Users: users})
		},
		"rest": func(t *testing.T, s *Service, spec *model.NodeSpec) {
			s.applyPullResult(context.Background(), pullResult{config: spec, configHash: computeConfigHash(spec), users: users, userHash: computeUserHash(users), gen: s.desiredGen})
		},
	}
	for name, deliver := range paths {
		t.Run(name, func(t *testing.T) {
			tk := newTestKernels()
			s := newTestService(t, tk)
			spec := ownedSpec(8443)
			want := computeConfigHash(spec)

			deliver(t, s, spec)
			if s.lastConfigHash != want {
				t.Fatalf("desired hash = %s, want the hash of the delivered config %s", s.lastConfigHash, want)
			}
			if !s.appliedState.Running || s.appliedState.ConfigHash != want {
				t.Fatalf("target not applied: %+v err=%v", s.appliedState, s.lastApplyErr)
			}

			scramble(spec)

			if s.lastConfig == spec {
				t.Fatal("the desired snapshot is the caller's own object")
			}
			assertUnscrambled(t, "desired", s.lastConfig, 8443)
			if got := computeConfigHash(s.lastConfig); got != s.lastConfigHash {
				t.Fatalf("desired snapshot hashes to %s but the recorded desired hash is %s", got, s.lastConfigHash)
			}
			assertUnscrambled(t, "applied", s.appliedState.Config, 8443)
			if got := computeConfigHash(s.appliedState.Config); got != s.appliedState.ConfigHash {
				t.Fatalf("applied snapshot hashes to %s but the recorded applied hash is %s", got, s.appliedState.ConfigHash)
			}
		})
	}
}

func TestPreparedHashDescribesThePreparedSnapshot(t *testing.T) {
	// A spec whose containers are empty but not nil: a copy that turned them
	// into nil would serialise differently and so hash differently.
	emptyContainers := func(port int) *model.NodeSpec {
		return &model.NodeSpec{
			Protocol: "vless", ServerPort: port, Network: "tcp",
			NetworkSettings:  map[string]any{},
			TLSSettings:      map[string]any{},
			CustomRoutes:     []map[string]any{},
			Routes:           []model.RouteRule{},
			CustomOutbounds:  []model.OutboundConfig{},
			CustomRouteRules: []model.CustomRouteRule{},
		}
	}
	for name, build := range map[string]func(int) *model.NodeSpec{"nested": ownedSpec, "empty containers": emptyContainers} {
		t.Run(name, func(t *testing.T) {
			tk := newTestKernels()
			s := newTestService(t, tk)
			spec := build(8443)
			callerHash := computeConfigHash(spec)

			prepared, err := s.prepareTarget(context.Background(), spec, []model.UserSpec{userA})
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			defer s.cert.Discard(prepared.cert)
			if prepared.spec == spec {
				t.Fatal("the prepared snapshot is the caller's own object")
			}
			if got := computeConfigHash(prepared.spec); got != prepared.configHash {
				t.Fatalf("prepared snapshot hashes to %s but the prepared hash is %s", got, prepared.configHash)
			}
			if prepared.configHash != callerHash {
				t.Fatalf("prepared hash %s differs from the hash of the delivered config %s: a repeated push of the same target would not be recognised", prepared.configHash, callerHash)
			}

			if name == "nested" {
				scramble(spec)
				assertUnscrambled(t, "prepared", prepared.spec, 8443)
				if got := computeConfigHash(prepared.spec); got != prepared.configHash {
					t.Fatalf("prepared hash no longer describes the prepared snapshot: %s vs %s", got, prepared.configHash)
				}
				if computeConfigHash(spec) == prepared.configHash {
					t.Fatal("sanity: mutating the caller's object must change its hash")
				}
			}
		})
	}
}

// After a successful apply the desired and applied hashes agree, so repeated
// pushes, 304 answers and the re-apply after a certificate renewal never
// rebuild an already applied target, while a real change still applies.
func TestAppliedTargetIsNotReappliedUntilItReallyChanges(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	ctx := context.Background()
	users := []model.UserSpec{userA}

	spec := ownedSpec(8443)
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: spec, Users: users})
	if !s.appliedState.Running {
		t.Fatalf("target not applied: %+v err=%v", s.appliedState, s.lastApplyErr)
	}
	_, reloads, _ := tk.singbox.counts()

	// The caller keeps its object and mutates it; the service must not notice.
	scramble(spec)

	// A repeated push of the recorded target and a 304 answer are no-ops.
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: ownedSpec(8443)})
	s.applyPullResult(ctx, pullResult{gen: s.desiredGen})
	if _, got, _ := tk.singbox.counts(); got != reloads {
		t.Fatalf("an already applied target was applied again: reloads %d → %d", reloads, got)
	}

	// A renewed certificate re-applies once; the hashes must agree again
	// afterwards so the next 304 does nothing.
	s.applyPullResult(ctx, pullResult{certChanged: true, gen: s.desiredGen})
	if _, got, _ := tk.singbox.counts(); got != reloads+1 {
		t.Fatalf("certificate renewal must re-apply exactly once: reloads %d → %d", reloads, got)
	}
	if s.appliedState.ConfigHash != s.lastConfigHash {
		t.Fatalf("after re-applying, applied hash %s != desired hash %s", s.appliedState.ConfigHash, s.lastConfigHash)
	}
	if s.appliedState.Config.ServerPort != 8443 {
		t.Fatalf("the re-apply used the caller's mutated object: port %d", s.appliedState.Config.ServerPort)
	}
	s.applyPullResult(ctx, pullResult{gen: s.desiredGen})
	s.reconcile(ctx)
	if _, got, _ := tk.singbox.counts(); got != reloads+1 {
		t.Fatalf("an already applied target was applied again after the renewal: reloads %d", got)
	}

	// A real change, in a nested field only, applies exactly once.
	changed := ownedSpec(8443)
	changed.TLSSettings["server_name"] = "renamed.example.test"
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: changed})
	if _, got, _ := tk.singbox.counts(); got != reloads+2 {
		t.Fatalf("a changed target must apply: reloads %d", got)
	}
	want := computeConfigHash(changed)
	if s.lastConfigHash != want || s.appliedState.ConfigHash != want || computeConfigHash(s.appliedState.Config) != want {
		t.Fatalf("hashes after the change: desired=%s applied=%s snapshot=%s want %s", s.lastConfigHash, s.appliedState.ConfigHash, computeConfigHash(s.appliedState.Config), want)
	}
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: changed})
	if _, got, _ := tk.singbox.counts(); got != reloads+2 {
		t.Fatalf("a repeated push of the changed target was applied again: reloads %d", got)
	}
}
