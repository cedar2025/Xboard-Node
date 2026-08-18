package kernel

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestUserDiffReplacesRotatedUUID(t *testing.T) {
	oldUser := model.UserSpec{ID: 5, UUID: "old-uuid"}
	newUser := model.UserSpec{ID: 5, UUID: "new-uuid"}

	toAdd, toRemove := UserDiff([]model.UserSpec{oldUser}, []model.UserSpec{newUser})

	if len(toAdd) != 1 || toAdd[0] != newUser {
		t.Fatalf("toAdd = %#v, want %#v", toAdd, []model.UserSpec{newUser})
	}
	if len(toRemove) != 1 || toRemove[0] != oldUser {
		t.Fatalf("toRemove = %#v, want %#v", toRemove, []model.UserSpec{oldUser})
	}
}

func TestUserDiffKeepsUnchangedUsers(t *testing.T) {
	user := model.UserSpec{ID: 5, UUID: "same-uuid"}

	toAdd, toRemove := UserDiff([]model.UserSpec{user}, []model.UserSpec{user})

	if len(toAdd) != 0 || len(toRemove) != 0 {
		t.Fatalf("unchanged user diff = add %#v, remove %#v; want no changes", toAdd, toRemove)
	}
}
