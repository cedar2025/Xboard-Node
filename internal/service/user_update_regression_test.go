package service

import (
	"context"
	"errors"
	"testing"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

// Native user errors reported by the kernel must never turn into an advanced
// applied user hash, on any input path. These tests drive the fake kernels;
// the xray package and the real-kernel tests cover the native side.

var rotatedA = model.UserSpec{ID: userA.ID, UUID: "cccccccc-0000-4000-8000-000000000000", SpeedLimit: userA.SpeedLimit}

// A rotated credential arriving as a delta "add" must never be applied with a
// plain AddUsers when the stale identity could not be removed first: sing-box's
// AddUsers ignores an ID it already serves, so the old credential would stay
// valid while the applied state claims the new one. The kernels' full replace
// performs the remove-before-add itself.
func TestApplyUserDeltaRotationNeverFallsThroughToPlainAdd(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA, userB})
	tk.singbox.removeErr = errors.New("remove failed")
	var replaced []model.UserSpec
	tk.singbox.onUpdateUsers = func(users []model.UserSpec) { replaced = model.CloneUserSpecs(users) }

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{rotatedA}})

	if tk.singbox.addCalls != 0 {
		t.Fatal("a plain AddUsers after the stale credential could not be removed leaves the old credential valid")
	}
	if computeUserHash(replaced) != computeUserHash([]model.UserSpec{rotatedA, userB}) {
		t.Fatalf("the kernel must receive the full rotated set, got %v", replaced)
	}
	if s.appliedState.UserHash != s.lastUserHash || computeUserHash(s.appliedState.Users) != computeUserHash([]model.UserSpec{rotatedA, userB}) {
		t.Fatalf("applied users = %v", s.appliedState.Users)
	}
	if start, _, _ := tk.singbox.counts(); start != 1 {
		t.Fatalf("a rotation must not restart the kernel, starts = %d", start)
	}
}

func TestNativeUserErrorsNeverBecomeSuccessOnAnyPath(t *testing.T) {
	type path struct {
		fail    func(k *fakeKernel)
		deliver func(s *Service)
		want    []model.UserSpec
	}
	updateFails := func(k *fakeKernel) { k.updateErr = errors.New("native update failed") }
	paths := map[string]path{
		"ws_delta_add": {
			fail: func(k *fakeKernel) { k.addErr = errors.New("native add failed"); updateFails(k) },
			deliver: func(s *Service) {
				s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 3, UUID: "dddddddd-0000-4000-8000-000000000000"}}})
			},
			want: []model.UserSpec{userA, userB, {ID: 3, UUID: "dddddddd-0000-4000-8000-000000000000"}},
		},
		"ws_delta_add_rotation": {
			fail: updateFails,
			deliver: func(s *Service) {
				s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{rotatedA}})
			},
			want: []model.UserSpec{rotatedA, userB},
		},
		"ws_delta_remove": {
			fail: func(k *fakeKernel) { k.removeErr = errors.New("native remove failed"); updateFails(k) },
			deliver: func(s *Service) {
				s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{userA}})
			},
			want: []model.UserSpec{userB},
		},
		"ws_full": {
			fail: updateFails,
			deliver: func(s *Service) {
				s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{userB}})
			},
			want: []model.UserSpec{userB},
		},
		"rest_full": {
			fail: updateFails,
			deliver: func(s *Service) {
				s.applyPullResult(context.Background(), pullResult{users: []model.UserSpec{userB}, userHash: computeUserHash([]model.UserSpec{userB}), gen: s.desiredGen})
			},
			want: []model.UserSpec{userB},
		},
	}
	for name, p := range paths {
		t.Run(name, func(t *testing.T) {
			tk := newTestKernels()
			s := newTestService(t, tk)
			seed(t, s, vlessSpec(443), []model.UserSpec{userA, userB})
			p.fail(tk.singbox)

			p.deliver(s)

			if computeUserHash(s.lastUsers) != computeUserHash(p.want) {
				t.Fatalf("desired users = %v, want %v kept for the retry", s.lastUsers, p.want)
			}
			if s.appliedState.UserHash != "" || len(s.appliedState.Users) != 0 || s.appliedState.Running {
				t.Fatalf("applied state advanced despite the native failure: %+v", s.appliedState)
			}
			if tk.singbox.IsRunning() {
				t.Fatal("a listener that cannot enforce the current user set must stop")
			}
			if !s.retryPending || s.lastApplyStage != "users" {
				t.Fatalf("retry pending=%v stage=%q", s.retryPending, s.lastApplyStage)
			}
			for _, u := range []model.UserSpec{userA, userB, rotatedA} {
				if s.speedTracker.GetLimiter(u.UUID) != nil {
					t.Fatalf("limiter for %s must be gone while nothing is served", u.UUID)
				}
			}

			// The kernel recovers: the pending retry starts it with exactly
			// the desired users.
			tk.singbox.updateErr, tk.singbox.addErr, tk.singbox.removeErr = nil, nil, nil
			s.reconcile(context.Background())
			if s.appliedState.UserHash != s.lastUserHash || s.retryPending || !tk.singbox.IsRunning() {
				t.Fatalf("retry did not apply the desired users: applied=%+v pending=%v err=%v", s.appliedState, s.retryPending, s.lastApplyErr)
			}
			if _, started := tk.singbox.startedWith(); computeUserHash(started) != computeUserHash(p.want) {
				t.Fatalf("kernel restarted with %v, want %v", started, p.want)
			}
		})
	}
}
