package main

import (
	"bytes"
	"embed"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

type event struct {
	SyscallID     uint32
	TracingStatus uint32
}

//go:embed output/*
var eBPFObject embed.FS
var version = "test"
var tracepointCategory = "raw_syscalls"
var tracepointName = "sys_enter"

func main() {

	functionName := flag.String("fn", "", "Name of the function to trace (mandatory)")
	outputFile := flag.String("o", "", "Output file to store the result")
	commandOutput := flag.Bool("co", false, "Print command output")
	// define usage
	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] [command]\n", path.Base(os.Args[0]))
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
		fmt.Printf("\nversion: %s\n", version)
	}

	flag.Parse()

	if !isRunningAsRoot() {
		fmt.Println("not enough privileges to run the program")
		os.Exit(1)
	}

	// Check if the -fn flag is provided and has a value
	if *functionName == "" {
		fmt.Println("flag -fn is mandatory, please provide function name to trace.")
		os.Exit(1)
	}

	// Get the remaining arguments as the command to execute
	command := flag.Args()
	// Check if there are any arguments after the -f flag
	if len(command) == 0 {
		fmt.Println("command argument is mandatory.")
		os.Exit(1)
	}

	// suppress libbpf log ouput
	libbpfgo.SetLoggerCbs(
		bpf.Callbacks{
			Log: func(level int, msg string) {
				return
			},
		},
	)

	objectFile, err := eBPFObject.ReadFile("output/ebpf.o")
	bpfModule, err := bpf.NewModuleFromBuffer(objectFile, "ebpf.o")
	if err != nil {
		fmt.Printf("error loading BPF object file: %v\n", err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	/*
		HashMap used for passing various configuration
		from user-space to kernel-space.
	*/
	config, err := bpfModule.GetMap("config_map")
	if err != nil {
		fmt.Printf("error retrieving map from BPF program: %v\n", err)
		os.Exit(-1)
	}

	bpfModule.BPFLoadObject()
	enterFuncProbe, err := bpfModule.GetProgram("enter_function")
	if err != nil {
		fmt.Printf("error loading program 'enter_function': %v\n", err)
		os.Exit(-1)
	}

	exitFuncProbe, err := bpfModule.GetProgram("exit_function")
	if err != nil {
		fmt.Printf("error loading program 'exit_function': %v\n", err)
		os.Exit(-1)
	}

	traceFunction, err := bpfModule.GetProgram("start_trace")
	if err != nil {
		fmt.Printf("error loading program 'start_trace': %v\n", err)
		os.Exit(-1)
	}

	offset, err := helpers.SymbolToOffset(command[0], *functionName)
	if err != nil {
		fmt.Printf("error finding %s function offset: %v\n", *functionName, err)
		os.Exit(-1)
	}
	enterLink, err := enterFuncProbe.AttachUprobe(-1, command[0], offset)
	if err != nil {
		fmt.Printf("error attaching uprobe at function: %s, offset: %d\n", *functionName, offset)
		os.Exit(-1)
	}
	defer enterLink.Destroy()

	/*
		Since the uretprobes doesn't work well with Go binaries,
		we are going to attach a uprobe ∀ RET instruction withing the
		traced function.
	*/
	exitLinks := make([]*bpf.BPFLink, 0)
	functionRetOffsets, err := getFunctionRetOffsets(command[0], *functionName)
	for _, offsetRet := range functionRetOffsets {
		exitLink, err := exitFuncProbe.AttachUprobe(-1, command[0], offset+uint32(offsetRet))
		exitLinks = append(exitLinks, exitLink)
		if err != nil {
			fmt.Printf("error attaching uprobe at function RET: %s, offset: %d", *functionName, offset+uint32(offsetRet))
			os.Exit(-1)
		}
		defer func() {
			for _, up := range exitLinks {
				up.Destroy()
			}
			return
		}()
	}

	traceLink, err := traceFunction.AttachTracepoint(tracepointCategory, tracepointName)
	if err != nil {
		fmt.Printf("error attaching tracepoint at event: %s:%s", tracepointCategory, tracepointName)
		os.Exit(-1)
	}
	defer traceLink.Destroy()

	/*
		Sending input argument to BPF program
		to instruct tracing specific command taken from cli.
	*/
	config_key_command := 0
	baseCommand := filepath.Base(command[0])
	baseCmd := append([]byte(baseCommand), 0)
	err = config.Update(unsafe.Pointer(&config_key_command), unsafe.Pointer(&baseCmd[0]))
	if err != nil {
		fmt.Printf("error updating config_map with values: %d - '%s', %v\n", config_key_command, baseCommand, err)
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	rb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1024)
	if err != nil {
		fmt.Println("error initializing PerfBuffer: %v\n", err)
		os.Exit(-1)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// run command that we want to trace
	go func() {
		cmd := exec.Command(command[0], command[1:]...)
		outErr, _ := cmd.CombinedOutput()
		if *commandOutput {
			fmt.Printf("%s\n", outErr)
		}
		defer cmd.Wait()
	}()

	var syscalls []uint32
	executionIsStarted := false
	go func() {
		for data := range eventsChannel {
			var e event
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
				fmt.Printf("failed to decode received data %q: %s\n", data, err)
				return
			}
			switch e.TracingStatus {
			case 1:
				executionIsStarted = true
			case 2:
				executionIsStarted = false

				// write to file or stdout depending on the flags passed
				if *outputFile != "" {
					file, _ := createFile(outputFile)
					defer file.Close()
					// write to file
					printSyscalls(file, syscalls)
				} else {
					// write to stdout
					printSyscalls(os.Stdout, syscalls)
				}

				// send an interrupt to gracefuly shutdown the program
				p, _ := os.FindProcess(os.Getpid())
				p.Signal(os.Interrupt)
			default:
				if executionIsStarted {
					syscalls = append(syscalls, e.SyscallID)
				}
			}
		}
	}()

	rb.Poll(300)
	<-c
	rb.Stop()
}
