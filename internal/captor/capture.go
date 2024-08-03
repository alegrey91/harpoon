package captor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	embedded "github.com/alegrey91/harpoon/internal/embeddable"
	"github.com/alegrey91/harpoon/internal/executor"
	probes "github.com/alegrey91/harpoon/internal/probesfacade"
	bpf "github.com/aquasecurity/libbpfgo"
)

var (
	bpfConfigMap       = "config_map"
	bpfEventsMap       = "events"
	uprobeEnterFunc    = "enter_function"
	uprobeExitFunc     = "exit_function"
	tracepointFunc     = "trace_syscall"
	tracepointCategory = "raw_syscalls"
	tracepointName     = "sys_enter"
)

type event struct {
	SyscallID uint32
}

type CaptureOptions struct {
	CommandOutput bool
	LibbpfOutput  bool
}

func Capture(functionSymbol string, cmdArgs []string, opts CaptureOptions) ([]uint32, error) {
	if !opts.LibbpfOutput {
		// suppress libbpf log ouput
		bpf.SetLoggerCbs(
			bpf.Callbacks{
				Log: func(level int, msg string) {
					return
				},
			},
		)
	}

	objectFile, err := embedded.BPFObject.ReadFile("output/ebpf.o")
	bpfModule, err := bpf.NewModuleFromBuffer(objectFile, "ebpf.o")
	if err != nil {
		return nil, fmt.Errorf("error loading BPF object file: %v", err)
	}
	defer bpfModule.Close()

	/*
		HashMap used for passing various configuration
		from user-space to ebpf program.
	*/
	config, err := bpfModule.GetMap(bpfConfigMap)
	if err != nil {
		return nil, fmt.Errorf("error retrieving map (%s) from BPF program: %v", bpfConfigMap, err)
	}
	enterFuncProbe, err := bpfModule.GetProgram(uprobeEnterFunc)
	if err != nil {
		return nil, fmt.Errorf("error loading program (%s): %v", uprobeEnterFunc, err)
	}
	exitFuncProbe, err := bpfModule.GetProgram(uprobeExitFunc)
	if err != nil {
		return nil, fmt.Errorf("error loading program (%s): %v", uprobeExitFunc, err)
	}
	traceFunction, err := bpfModule.GetProgram(tracepointFunc)
	if err != nil {
		return nil, fmt.Errorf("error loading program (%s): %v", tracepointFunc, err)
	}

	bpfModule.BPFLoadObject()
	offset, err := probes.AttachUProbe(cmdArgs[0], functionSymbol, enterFuncProbe)
	if err != nil {
		return nil, fmt.Errorf("error attaching uprobe to %s: %v", functionSymbol, err)
	}

	err = probes.AttachURETProbe(cmdArgs[0], functionSymbol, exitFuncProbe, offset)
	if err != nil {
		return nil, fmt.Errorf("error attaching uretprobe to %s: %v", functionSymbol, err)
	}

	traceLink, err := traceFunction.AttachTracepoint(tracepointCategory, tracepointName)
	if err != nil {
		return nil, fmt.Errorf("error attaching tracepoint at event (%s:%s): %v", tracepointCategory, tracepointName, err)
	}
	defer traceLink.Destroy()

	/*
		Sending input argument to BPF program
		to instruct tracing specific args taken from cli.
	*/
	config_key_args := 0
	baseargs := filepath.Base(cmdArgs[0])
	baseCmd := append([]byte(baseargs), 0)
	err = config.Update(unsafe.Pointer(&config_key_args), unsafe.Pointer(&baseCmd[0]))
	if err != nil {
		return nil, fmt.Errorf("error updating map (%s) with values %d / %s: %v", bpfConfigMap, config_key_args, baseargs, err)
	}

	// init perf buffer
	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	rb, err := bpfModule.InitPerfBuf(bpfEventsMap, eventsChannel, lostChannel, 1)
	if err != nil {
		return nil, fmt.Errorf("error initializing map (%s) with PerfBuffer: %v", bpfEventsMap, err)
	}

	// run args that we want to trace
	var wg sync.WaitGroup
	wg.Add(1)
	go executor.Run(cmdArgs, opts.CommandOutput, &wg)

	var syscalls []uint32
	go func() {
		for {
			select {
			case data := <-eventsChannel:
				var e event
				err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error reading event: %v\n", err)
					return
				}
				syscalls = append(syscalls, e.SyscallID)
			case lost := <-lostChannel:
				fmt.Fprintf(os.Stderr, "lost %d data\n", lost)
				return
			}
		}
	}()

	rb.Poll(300)
	// wait for args completion
	wg.Wait()
	rb.Stop()

	return syscalls, nil
}
