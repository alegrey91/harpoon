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
	var err error
	var allSymbs []elf.Symbol
	var goSymbs []elf.Symbol

	goElf, err := elf.Open(elfFile)
	if err != nil {
		return []uint64{}, err
	}
	goSymbs, err = goElf.Symbols()
	if len(goSymbs) > 0 {
		allSymbs = append(allSymbs, goSymbs...)
	}
	goDynamicSymbs, _ := goElf.DynamicSymbols()
	if len(goDynamicSymbs) > 0 {
		allSymbs = append(allSymbs, goDynamicSymbs...)
	}

	if len(allSymbs) == 0 {
		return nil, fmt.Errorf("symbol is empty")
	}

	var found bool
	var symbol elf.Symbol
	for _, s := range allSymbs {
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

	var offsets []uint64
	var instHex []byte
	instHex = elfText[start:end]
	offsets, _ = decodeInstruction(instHex)
	if len(offsets) == 0 {
		return offsets, fmt.Errorf("no RET instructions found")
	}

	address := symbol.Value
	for _, prog := range goElf.Progs {
		// Skip uninteresting segments.
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= symbol.Value && symbol.Value < (prog.Vaddr+prog.Memsz) {
			// stackoverflow.com/a/40249502
			address = symbol.Value - prog.Vaddr + prog.Off
			break
		}
	}
	for i, offset := range offsets {
		offsets[i] = address + offset
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
