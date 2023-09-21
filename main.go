package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"path/filepath"

	"github.com/iovisor/gobpf/bcc"
	seccomp "github.com/seccomp/libseccomp-golang"
)

type event struct {
	// syscall number
	ID uint32
	// Stops tracing syscalls if true
	TracingStatus uint32
}

//go:embed ebpf.c.txt
var eBPFCode string

func main() {

	functionName := flag.String("f", "", "Name of the function to trace (mandatory)")
	outputFile := flag.String("o", "", "Name of the output file")
	flag.Parse()

	// Check if the -f flag is provided and has a value
	if *functionName == "" {
		fmt.Println("Error: -f flag is mandatory. Please provide the name of the function to trace.")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *outputFile != "" {
		// Redirect standard output to the specified file
		outFile, err := os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			flag.PrintDefaults()
			os.Exit(1)
		}
		defer outFile.Close()
		os.Stdout = outFile
	}

	// Get the remaining arguments as the command to execute
	command := flag.Args()
	// Check if there are any arguments after the -f flag
	if len(command) == 0 {
		fmt.Println("Error: Command to execute is mandatory. Please provide the command.")
		flag.PrintDefaults()
		os.Exit(1)
	}
	
	src := strings.Replace(eBPFCode, "$CMD", filepath.Base(command[0]), -1)
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

	syscalls := make(map[uint32]int)
	go func() {
		for data := range channel {
			var e event
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
				fmt.Printf("failed to decode received data %q: %s\n", data, err)
				return
			}
			switch e.TracingStatus {
			case 1:
				if *outputFile == "" {
					fmt.Println("[+] start tracing")
				}
			case 2:
				if *outputFile == "" {
					fmt.Println("[+] stop tracing")
					fmt.Println("[ syscall list ]")
				}
				printSyscalls(syscalls)
				p, _ := os.FindProcess(os.Getpid())
				p.Signal(os.Interrupt)
			default:
				syscalls[e.ID]++
			}
		}
	}()

	perfMap.Start()
	<-c
	perfMap.Stop()
}

func printSyscalls(syscalls map[uint32]int) {
	for s := range syscalls {
		syscall, err := seccomp.ScmpSyscall(s).GetName()
		if err != nil {
			fmt.Printf("error: %v", err)
		}
		fmt.Println(syscall)
	}
}
