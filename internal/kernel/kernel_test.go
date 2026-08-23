package kernel

import (
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

// Regression test for cedar2025/Xboard-Node#53:
// rotating a user's UUID must remove the old identity before adding the
// new one, otherwise kernels report "AddUser failed: user already exists"
// and the stale UUID keeps working.
func TestUserDiff_UUIDRotation(t *testing.T) {
	oldUsers := []model.UserSpec{
		{ID: 1, UUID: "old-uuid"},
		{ID: 2, UUID: "keep-uuid"},
	}
	newUsers := []model.UserSpec{
		{ID: 1, UUID: "new-uuid"},
		{ID: 2, UUID: "keep-uuid"},
	}

	toAdd, toRemove := UserDiff(oldUsers, newUsers)

	wantAdd := []model.UserSpec{{ID: 1, UUID: "new-uuid"}}
	if !reflect.DeepEqual(toAdd, wantAdd) {
		t.Errorf("toAdd = %v, want %v", toAdd, wantAdd)
	}

	// The stale identity for the same ID must be removed so kernels can
	// apply remove-then-add ordering.
	wantRemove := []model.UserSpec{{ID: 1, UUID: "old-uuid"}}
	if !reflect.DeepEqual(toRemove, wantRemove) {
		t.Errorf("toRemove = %v, want %v (stale UUID must be removed on rotation)", toRemove, wantRemove)
	}
}

func TestUserDiff_AddRemoveUnchanged(t *testing.T) {
	oldUsers := []model.UserSpec{
		{ID: 1, UUID: "a"},
		{ID: 2, UUID: "b"},
	}
	newUsers := []model.UserSpec{
		{ID: 2, UUID: "b"},
		{ID: 3, UUID: "c"},
	}

	toAdd, toRemove := UserDiff(oldUsers, newUsers)

	wantAdd := []model.UserSpec{{ID: 3, UUID: "c"}}
	if !reflect.DeepEqual(toAdd, wantAdd) {
		t.Errorf("toAdd = %v, want %v", toAdd, wantAdd)
	}
	wantRemove := []model.UserSpec{{ID: 1, UUID: "a"}}
	if !reflect.DeepEqual(toRemove, wantRemove) {
		t.Errorf("toRemove = %v, want %v", toRemove, wantRemove)
	}

	// Identical sets → no diff.
	toAdd, toRemove = UserDiff(newUsers, newUsers)
	if len(toAdd) != 0 || len(toRemove) != 0 {
		t.Errorf("identical sets should produce empty diff, got add=%v remove=%v", toAdd, toRemove)
	}
}
