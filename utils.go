package main

import (
	"fmt"
	"os/user"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// printSyscalls takes a slice of syscall ids and print them out
// converting the ids to their equivalent name.
// e.g. id=1 -> syscall=write
func printSyscalls(syscalls []uint32) {
	for _, s := range syscalls {
		syscall, err := seccomp.ScmpSyscall(s).GetName()
		if err != nil {
			fmt.Printf("error: %v", err)
		}
		fmt.Println(syscall)
	}
}

// isRunningAsRoot check if the program is executed as root.
// Returns true in case we are running it as root, else otherwise.
func isRunningAsRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
		return false
	}
	return currentUser.Uid == "0"
}
