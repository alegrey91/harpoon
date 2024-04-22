package privileged

import (
	"os/user"
)

// IsRunningAsRoot check if the program is executed as root.
// Returns true in case we are running it as root, else otherwise.
func IsRunningAsRoot(currentUser *user.User) bool {
	return currentUser.Uid == "0"
}
