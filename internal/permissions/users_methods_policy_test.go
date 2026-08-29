package permissions

import (
	"testing"

	"github.com/nextlevelbuilder/goclaw/pkg/protocol"
)

// MethodRole is fail-closed: a method missing from the admin allowlist falls
// through to RoleNone, which CanAccess denies for every role including owner.
// The failure shows up as a permission error rather than a routing error, so
// it is easy to misdiagnose as broken auth. This test pins each users.* method
// to the classification it needs.
func TestMethodRole_UsersMethodsAreAdmin(t *testing.T) {
	methods := []string{
		protocol.MethodUsersList,
		protocol.MethodUsersGet,
		protocol.MethodUsersCreate,
		protocol.MethodUsersUpdate,
		protocol.MethodUsersDelete,
		protocol.MethodUsersPasswordSet,
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			if got := MethodRole(method); got != RoleAdmin {
				t.Errorf("MethodRole(%q) = %q, want %q", method, got, RoleAdmin)
			}
		})
	}
}

func TestCanAccess_UsersMethods(t *testing.T) {
	engine := NewPolicyEngine(nil)

	tests := []struct {
		role Role
		want bool
	}{
		{RoleOwner, true},
		{RoleAdmin, true},
		{RoleOperator, false},
		{RoleViewer, false},
		{RoleNone, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			if got := engine.CanAccess(tt.role, protocol.MethodUsersCreate); got != tt.want {
				t.Errorf("CanAccess(%q, users.create) = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}
