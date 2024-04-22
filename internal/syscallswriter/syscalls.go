package syscalls

import (
	"fmt"
	"io"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// Print takes an io.Writer and slice of syscall ids,
// to print them on the writer (this could be a file or stdout).
// it convert the ids to their equivalent name.
// e.g. id=1 -> syscall=write
func Print(writer io.Writer, syscalls []uint32) error {
	for _, s := range syscalls {
		syscall, err := seccomp.ScmpSyscall(s).GetName()
		if err != nil {
			return fmt.Errorf("error finding syscall %d: %v", s, err)
		}
		fmt.Fprintln(writer, syscall)
	}
	return nil
}
