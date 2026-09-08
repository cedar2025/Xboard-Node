package kernel

import (
	"github.com/cedar2025/xboard-node/internal/model"
	"testing"
)

func TestUserDiffIncludesBothSidesOfCredentialRotation(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: "old-test-credential"}
	next := model.UserSpec{ID: 1, UUID: "new-test-credential"}
	add, remove := UserDiff([]model.UserSpec{old}, []model.UserSpec{next})
	if len(add) != 1 || add[0].UUID != next.UUID || len(remove) != 1 || remove[0].UUID != old.UUID {
		t.Fatalf("rotation must remove the old identity before adding the new one: add=%v remove=%v", add, remove)
	}
}

func TestUserDiffDoesNotReplaceAnIdentityForLimitChanges(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: "test-credential", SpeedLimit: 1}
	next := old
	next.SpeedLimit = 2
	add, remove := UserDiff([]model.UserSpec{old}, []model.UserSpec{next})
	if len(add) != 0 || len(remove) != 0 {
		t.Fatalf("limit change is not a credential rotation: add=%v remove=%v", add, remove)
	}
}
