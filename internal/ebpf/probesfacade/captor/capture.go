package captor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	probes "github.com/alegrey91/harpoon/internal/ebpf/probesfacade"
	embedded "github.com/alegrey91/harpoon/internal/embeddable"
	"github.com/alegrey91/harpoon/internal/executor"
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
	CommandError  bool
	LibbpfOutput  bool
	Interval      int
}

type ebpfSetup struct {
	mod      *bpf.Module
	link     *bpf.BPFLink
	pb       *bpf.PerfBuffer
	eventsCh chan []byte
	lostCh   chan uint64
	opts     CaptureOptions
	cmd      []string
}

// InitProbes setup the ebpf module attaching probes and tracepoints
// to the ebpf program.
// Returns the ebpfSetup struct in case of seccess, an error in case of failure.
func InitProbes(functionSymbol string, cmdArgs []string, opts CaptureOptions) (*ebpfSetup, error) {
	if len(cmdArgs) == 0 {
		return nil, errors.New("error no arguments provided, at least 1 argument is required")
	}

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
	pb, err := bpfModule.InitPerfBuf(bpfEventsMap, eventsChannel, lostChannel, 1)
	if err != nil {
		return nil, fmt.Errorf("error initializing map (%s) with PerfBuffer: %v", bpfEventsMap, err)
	}

	return &ebpfSetup{
		mod:      bpfModule,
		link:     traceLink,
		pb:       pb,
		eventsCh: eventsChannel,
		lostCh:   lostChannel,
		opts:     opts,
		cmd:      cmdArgs,
	}, nil
}

// Close closes the ebpf link and module.
func (ebpf *ebpfSetup) Close() {
	ebpf.link.Destroy()
	ebpf.mod.Close()
}

// Capture collects syscalls from the executed command.
// Returns values through the given channels.
// When the interval is 0, automatically closes the channels.
func (ebpf *ebpfSetup) Capture(ctx context.Context, resultCh chan []uint32, errorCh chan error) {
	// setting up ticker to dump results
	// every interval of time.
	var ticker *time.Ticker
	var interval time.Duration
	if ebpf.opts.Interval > 0 {
		interval = time.Duration(ebpf.opts.Interval) * time.Second
	} else {
		// wait what? ~114 years of interval?
		// yes, so that the ticker will never be triggered.
		// the value looks reasonably good.
		interval = time.Duration(1000000) * time.Hour
	}
	ticker = time.NewTicker(interval)
	defer ticker.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	cmdStdoutCh := make(chan string)
	cmdStderrCh := make(chan string)
	// running command to trace its syscalls
	go executor.Run(
		ebpf.cmd,
		ebpf.opts.CommandOutput,
		ebpf.opts.CommandError,
		&wg,
		cmdStdoutCh,
		cmdStderrCh,
	)

	var syscalls []uint32
	go func() {
		for {
			select {
			case data := <-ebpf.eventsCh:
				var e event
				err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
				if err != nil {
					//fmt.Fprintf(os.Stderr, "error reading event: %v\n", err)
					// will be left empty for now.
					return
				}
				syscalls = append(syscalls, e.SyscallID)
			case <-ticker.C:
				// used to send incremental result
				// every interval of time.
				resultCh <- syscalls
				// we clear the slice after sending data
				// to the channel, so on the next iteration
				// this will have only the most recent values.
				syscalls = nil
			case _ = <-ebpf.lostCh:
				// managing errors from libbpf
				// will be left empty for now.
				//fmt.Fprintf(os.Stderr, "lost %d data\n", lost)
				return
			case line, ok := <-cmdStdoutCh:
				// managing stdout from executed command
				if !ok {
					break
				}
				fmt.Println("stdout:", line)
			case err, ok := <-cmdStderrCh:
				// managing stderr from executed command
				if !ok {
					break
				}
				fmt.Println("stderr:", err)
			}
		}
	}()

	ebpf.pb.Poll(300)
	// wait for args completion
	wg.Wait()
	close(cmdStdoutCh)
	close(cmdStderrCh)
	ebpf.pb.Stop()

	// sending last remained syscalls
	// and close the channel.
	resultCh <- syscalls
	close(resultCh)
	close(errorCh)
}
