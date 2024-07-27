package captor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/alegrey91/harpoon/internal/archiver"
	embedded "github.com/alegrey91/harpoon/internal/embeddable"
	"github.com/alegrey91/harpoon/internal/executor"
	probes "github.com/alegrey91/harpoon/internal/probesfacade"
	syscallsw "github.com/alegrey91/harpoon/internal/syscallswriter"
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
	Save          bool
	Directory     string
}

func Capture(functionSymbols string, cmdArgs []string, opts CaptureOptions) {
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

	functionSymbolList := strings.Split(functionSymbols, ",")

	objectFile, err := embedded.BPFObject.ReadFile("output/ebpf.o")
	bpfModule, err := bpf.NewModuleFromBuffer(objectFile, "ebpf.o")
	if err != nil {
		fmt.Printf("error loading BPF object file: %v\n", err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	/*
		HashMap used for passing various configuration
		from user-space to ebpf program.
	*/
	config, err := bpfModule.GetMap(bpfConfigMap)
	if err != nil {
		fmt.Printf("error retrieving map (%s) from BPF program: %v\n", bpfConfigMap, err)
		os.Exit(-1)
	}
	enterFuncProbe, err := bpfModule.GetProgram(uprobeEnterFunc)
	if err != nil {
		fmt.Printf("error loading program (%s): %v\n", uprobeEnterFunc, err)
		os.Exit(-1)
	}
	exitFuncProbe, err := bpfModule.GetProgram(uprobeExitFunc)
	if err != nil {
		fmt.Printf("error loading program (%s): %v\n", uprobeExitFunc, err)
		os.Exit(-1)
	}
	traceFunction, err := bpfModule.GetProgram(tracepointFunc)
	if err != nil {
		fmt.Printf("error loading program (%s): %v\n", tracepointFunc, err)
		os.Exit(-1)
	}

	bpfModule.BPFLoadObject()
	for _, functionSymbol := range functionSymbolList {
		offset, err := probes.AttachUProbe(cmdArgs[0], functionSymbol, enterFuncProbe)
		if err != nil {
			fmt.Printf("error attaching uprobe to %s: %v", functionSymbol, err)
			os.Exit(-1)
		}

		err = probes.AttachURETProbe(cmdArgs[0], functionSymbol, exitFuncProbe, offset)
		if err != nil {
			fmt.Printf("error attaching uretprobe to %s: %v", functionSymbol, err)
			os.Exit(-1)
		}
	}

	traceLink, err := traceFunction.AttachTracepoint(tracepointCategory, tracepointName)
	if err != nil {
		fmt.Printf("error attaching tracepoint at event (%s:%s): %v\n", tracepointCategory, tracepointName, err)
		os.Exit(-1)
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
		fmt.Printf("error updating map (%s) with values %d / %s: %v\n", bpfConfigMap, config_key_args, baseargs, err)
		os.Exit(-1)
	}

	// init perf buffer
	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	rb, err := bpfModule.InitPerfBuf(bpfEventsMap, eventsChannel, lostChannel, 1)
	if err != nil {
		fmt.Printf("error initializing map (%s) with PerfBuffer: %v\n", bpfEventsMap, err)
		os.Exit(-1)
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

	var errOut error
	if opts.Save {
		fileName := archiver.Convert(functionSymbolList[0])
		err := os.MkdirAll(opts.Directory, os.ModePerm)
		if err != nil {
			fmt.Printf("error creating directory: %v\n", err)
			os.Exit(-1)
		}
		file, err := os.Create(path.Join(opts.Directory, fileName))
		if err != nil {
			fmt.Printf("error creating file %s: %v\n", file.Name(), err)
			os.Exit(-1)
		}
		defer file.Close()

		if err := file.Chmod(0744); err != nil {
			fmt.Printf("error setting permissions to %s: %v\n", file.Name(), err)
		}
		// write to file
		errOut = syscallsw.Print(file, syscalls)
	} else {
		// write to stdout
		errOut = syscallsw.Print(os.Stdout, syscalls)
	}
	if errOut != nil {
		fmt.Printf("error printing out system calls: %v\n", errOut)
		os.Exit(-1)
	}
}
