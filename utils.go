package main

import (
	"fmt"
	"io"
	"os"
	"os/user"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// printSyscalls takes an io.Writer and slice of syscall ids,
// to print them on the writer (this could be a file or stdout).
// it convert the ids to their equivalent name.
// e.g. id=1 -> syscall=write
func printSyscalls(writer io.Writer, syscalls []uint32) {
	for _, s := range syscalls {
		syscall, err := seccomp.ScmpSyscall(s).GetName()
		if err != nil {
			fmt.Printf("error: %v", err)
		}
		fmt.Fprintln(writer, syscall)
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

// create a file and return the resultant *os.File object.
// returns an error in case of fail.
func createFile(outputFile *string) (*os.File, error) {
	file, err := os.Create(*outputFile)
	if err != nil {
		return nil, fmt.Errorf("error: %v", err)
	}
	return file, nil
}
