package elfreader

import (
	"bytes"
	"debug/elf"
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// GetFunctionRetOffsets returns the list of offsets
// where RET instruction appear within the function.
// This code was taken from here:
// https://github.com/cfc4n/go_uretprobe_demo/blob/master/ret_offset.go#L22
func GetFunctionRetOffsets(elfFile string, fnName string) ([]uint64, error) {
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

	instHex := elfText[start:end]
	var offsets []uint64
	offsets, err = decodeInstruction(instHex)
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
func decodeInstruction(instHex []byte) ([]uint64, error) {
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
