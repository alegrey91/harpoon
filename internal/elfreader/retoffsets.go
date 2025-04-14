package elfreader

import (
	"bytes"
	"debug/elf"
	"fmt"
	"golang.org/x/arch/arm64/arm64asm"

	"golang.org/x/arch/x86/x86asm"
)

// GetFunctionRetOffsets returns the list of offsets
// where RET instruction appear within the function.
// This code was taken from here:
// https://github.com/cfc4n/go_uretprobe_demo/blob/master/ret_offset.go#L22
func GetFunctionRetOffsets(elfFile string, fnName string) ([]uint64, error) {
	var goSymbs []elf.Symbol
	var goElf *elf.File
	var goArch elf.Machine
	goElf, err := elf.Open(elfFile)
	if err != nil {
		return []uint64{}, err
	}
	goSymbs, err = goElf.Symbols()
	if err != nil {
		return nil, err
	}
	goArch = goElf.Machine
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

	instHex := elfText[start:end]
	var offsets []uint64
	offsets, err = decodeInstruction(instHex, goArch)
	if err != nil {
		return nil, fmt.Errorf("error decoding instruction: %v", err)
	}
	if len(offsets) == 0 {
		return offsets, fmt.Errorf("no RET instructions found")
	}

	return offsets, nil
}

// this code was taken from here:
// https://github.com/cfc4n/go_uretprobe_demo/blob/master/ret_offset.go#L70C1-L91C2
func isNotNull(slice []byte) bool {
	for _, b := range slice {
		if b != 0x00 {
			return true
		}
	}
	fmt.Printf("Warning: udf instruction detected\n")
	return false
}
func decodeInstruction(instHex []byte, arch elf.Machine) ([]uint64, error) {
	switch arch {
	case elf.EM_X86_64:
		return decodeInstructionX86_64(instHex)
	case elf.EM_ARM:
		return decodeInstructionArm64(instHex)
	case elf.EM_AARCH64:
		return decodeInstructionArm64(instHex)
	default:
		return nil, fmt.Errorf("unsupported architecture")
	}
}
func decodeInstructionX86_64(instHex []byte) ([]uint64, error) {
	var offsets []uint64
	s := bytes.NewBufferString("")
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

func decodeInstructionArm64(instHex []byte) ([]uint64, error) {
	var offsets []uint64
	s := bytes.NewBufferString("")
	for i := 0; i < len(instHex); {
		inst, err := arm64asm.Decode(instHex[i:])
		if err != nil && isNotNull(instHex[i:i+4]) {
			return nil, err
		}
		if inst.Op == arm64asm.RET {
			offsets = append(offsets, uint64(i))
		}
		s.WriteString(fmt.Sprintf("%04X\t%s", i, inst.Op.String()))
		s.WriteString("\n")
		i += 4
	}
	return offsets, nil
}
