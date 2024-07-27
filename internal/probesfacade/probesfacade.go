package probesfacade

import (
	"fmt"

	"github.com/alegrey91/harpoon/internal/elfreader"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

// AttachUProbe attach one uprobe to the haed of the symbol function.
func AttachUProbe(binPath, functionSymbol string, probe *bpf.BPFProg) (uint32, error) {
	offset, err := helpers.SymbolToOffset(binPath, functionSymbol)
	if err != nil {
		return 0, fmt.Errorf("error finding function (%s) offset: %v\n", functionSymbol, err)
	}
	_, err = probe.AttachUprobe(-1, binPath, offset)
	if err != nil {
		return 0, fmt.Errorf("error attaching uprobe at function (%s) offset: %d, error: %v\n", functionSymbol, offset, err)
	}
	return offset, nil
}

// AttachURETProbe attach N uprobes to the RET instructions of the symbol function.
// Since the uretprobes doesn't work well with Go binaries,
// I preferred to create an abstraction to attach a uprobe ∀ RET instruction withing the traced function,
// instead of attachin a single uretprobe.
func AttachURETProbe(binPath, functionSymbol string, probe *bpf.BPFProg, offset uint32) error {
	functionRetOffsets, err := elfreader.GetFunctionRetOffsets(binPath, functionSymbol)
	if err != nil {
		return fmt.Errorf("error finding function (%s) RET offsets: %v\n", err)
	}
	for _, offsetRet := range functionRetOffsets {
		_, err := probe.AttachUprobe(-1, binPath, offset+uint32(offsetRet))
		if err != nil {
			return fmt.Errorf("error attaching uprobe at function (%s) RET: %d, error: %v\n", functionSymbol, offset+uint32(offsetRet), err)
		}
	}
	return nil
}
