package privileged

import (
	"os/user"
	"testing"
)

func TestIsRunningAsRoot(t *testing.T) {
	tests := []struct {
		name        string
		currentUser *user.User
		want        bool
	}{
		// TODO: Add test cases.
		{
			name: "is_running_as_root",
			currentUser: &user.User{
				Uid: "0",
			},
			want: true,
		},
		{
			name: "is_not_running_as_root",
			currentUser: &user.User{
				Uid: "1001",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRunningAsRoot(tt.currentUser); got != tt.want {
				t.Errorf("IsRunningAsRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}
