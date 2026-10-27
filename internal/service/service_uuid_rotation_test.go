package service

import (
	"context"
	"testing"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestWSUUIDDeltaUsesFullUpdateWithoutRemovingLastUser(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	old := model.UserSpec{ID: 1, UUID: "uuid-old", SpeedLimit: 4}
	replacement := model.UserSpec{ID: 1, UUID: "uuid-new", SpeedLimit: 8}
	s.lastConfig = &model.NodeSpec{Protocol: "vless", ServerPort: 10001}
	s.updateUserState([]model.UserSpec{old})
	k.onRemoveUsers = func([]model.UserSpec) { k.running = false }
	k.onUpdateUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0] != replacement {
			t.Fatalf("wrong replacement snapshot: %#v", users)
		}
	}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{replacement}})
	if k.removeCalls != 0 || k.addCalls != 0 || k.updateCalls != 1 {
		t.Fatalf("UUID replacement should use one full update: remove=%d add=%d update=%d", k.removeCalls, k.addCalls, k.updateCalls)
	}
	if !k.IsRunning() || k.startCalls != 0 {
		t.Fatal("UUID replacement stopped or restarted the listener")
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0] != replacement {
		t.Fatal("new UUID did not reach service state")
	}
	if s.lastUserHash != computeUserHash([]model.UserSpec{replacement}) {
		t.Fatal("user hash not updated")
	}
}
