package kernel

import (
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestUserDiffReplacesChangedUUID(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: "old-uuid"}
	replacement := model.UserSpec{ID: 1, UUID: "new-uuid"}
	unchanged := model.UserSpec{ID: 2, UUID: "unchanged"}
	added, removed := UserDiff([]model.UserSpec{old, unchanged}, []model.UserSpec{replacement, unchanged})
	if !reflect.DeepEqual(added, []model.UserSpec{replacement}) || !reflect.DeepEqual(removed, []model.UserSpec{old}) {
		t.Fatalf("UUID replacement diff = add %#v, remove %#v; want new identity added and old identity removed", added, removed)
	}
}

func TestUserDiffPreservesIdentityForLimitChanges(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: "same-uuid", SpeedLimit: 1, DeviceLimit: 1}
	updated := old
	updated.SpeedLimit, updated.DeviceLimit = 10, 3
	added, removed := UserDiff([]model.UserSpec{old}, []model.UserSpec{updated})
	if len(added) != 0 || len(removed) != 0 {
		t.Fatalf("limit change replaced identity: +%d -%d", len(added), len(removed))
	}
}
