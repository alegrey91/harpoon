package main

import (
	"bytes"
	"embed"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"

	"github.com/iovisor/gobpf/bcc"
)

type event struct {
	// syscall number
	SyscallID uint32
	// Stops tracing syscalls if true
	TracingStatus uint32
}

//go:embed ebpf/*
var eBPFDir embed.FS

func main() {

	functionName := flag.String("f", "", "Name of the function to trace (mandatory)")
	// define usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options] [command]\n", path.Base(os.Args[0]))
		fmt.Printf("\nOptions:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if !isRunningAsRoot() {
		fmt.Println("Not enough privileges to run the program")
		os.Exit(1)
	}

	// Check if the -f flag is provided and has a value
	if *functionName == "" {
		fmt.Println("Error: -f flag is mandatory. Please provide the name of the function to trace.")
		os.Exit(1)
	}

	// Get the remaining arguments as the command to execute
	command := flag.Args()
	// Check if there are any arguments after the -f flag
	if len(command) == 0 {
		fmt.Println("Error: Command to execute is mandatory. Please provide the command.")
		os.Exit(1)
	}

	source, _ := eBPFDir.ReadFile("ebpf/ebpf.c")
	src := strings.Replace(string(source), "$CMD", filepath.Base(command[0]), -1)
	bpfModule := bcc.NewModule(src, []string{})
	defer bpfModule.Close()

	uprobeFd, err := bpfModule.LoadUprobe("enter_function")
	if err != nil {
		log.Fatal(err)
	}
	uretprobeFd, err := bpfModule.LoadUprobe("exit_function")
	if err != nil {
		log.Fatal(err)
	}
	startTrace, err := bpfModule.LoadTracepoint("start_trace")
	if err != nil {
		log.Fatal(err)
	}

	err = bpfModule.AttachUprobe(command[0], *functionName, uprobeFd, -1)
	if err != nil {
		log.Fatal(err)
	}
	err = bpfModule.AttachUretprobe(command[0], *functionName, uretprobeFd, -1)
	if err != nil {
		log.Fatal(err)
	}
	if err := bpfModule.AttachTracepoint("raw_syscalls:sys_enter", startTrace); err != nil {
		log.Fatal(err)
	}

	table := bcc.NewTable(bpfModule.TableId("events"), bpfModule)
	channel := make(chan []byte)

	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// run command that we want to trace
	go func() {
		cmd := exec.Command(command[0], command[1:]...)
		cmd.Run()
		defer cmd.Wait()
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	}()

	var syscalls []uint32
	executionStarted := false
	go func() {
		for data := range channel {
			var e event
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
				fmt.Printf("failed to decode received data %q: %s\n", data, err)
				return
			}
			switch e.TracingStatus {
			case 1:
				fmt.Fprintln(os.Stderr, "[+] start tracing")
				executionStarted = true
			case 2:
				fmt.Fprintln(os.Stderr, "[+] stop tracing")
				executionStarted = false
				printSyscalls(syscalls)
				p, _ := os.FindProcess(os.Getpid())
				p.Signal(os.Interrupt)
			default:
				if executionStarted {
					syscalls = append(syscalls, e.SyscallID)
				}
			}
		}
	}()

	perfMap.Start()
	<-c
	perfMap.Stop()
}
