package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"os/user"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/arch/x86/x86asm"
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

func getFunctionRetOffsets(elfFile string, fnName string) ([]uint64, error) {
	// this code was taken from here:
	// https://github.com/cfc4n/go_uretprobe_demo/blob/master/ret_offset.go#L22
	var goSymbs []elf.Symbol
	var goElf *elf.File
	goElf, err := elf.Open(elfFile)
	if err != nil {
		return []uint64{}, err
	}
	goSymbs, err = goElf.Symbols()
	if err != nil {
		return nil, err
	}

	var found bool
	var symbol elf.Symbol
	for _, s := range goSymbs {
		if s.Name == fnName {
			symbol = s
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("symbol not found")
	}

	section := goElf.Sections[symbol.Section]

	var elfText []byte
	elfText, err = section.Data()
	if err != nil {
		return nil, err
	}

	start := symbol.Value - section.Addr
	end := start + symbol.Size

	var instHex []byte
	instHex = elfText[start:end]
	var offsets []uint64
	offsets, err = decodeInstruction(instHex)
	if len(offsets) == 0 {
		return offsets, fmt.Errorf("no RET instructions found")
	}

	return offsets, nil
}

func decodeInstruction(instHex []byte) ([]uint64, error) {
	// this code was taken from here:
	// https://github.com/cfc4n/go_uretprobe_demo/blob/master/ret_offset.go#L70C1-L91C2
	var offsets []uint64
	var s *bytes.Buffer
	s = bytes.NewBufferString("")
	for i := 0; i < len(instHex); {
		inst, err := x86asm.Decode(instHex[i:], 64)
		s.WriteString(fmt.Sprintf("%04X\t%s", i, inst.String()))
		s.WriteString("\n")
		if err != nil {
			return nil, err
		}
		if inst.Op == x86asm.RET {
			offsets = append(offsets, uint64(i))
		}
		i += inst.Len
	}

	return offsets, nil
}
