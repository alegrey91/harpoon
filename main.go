package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/ebpf.c -- -I../headers

type event struct {
	// syscall number
	SyscallID uint32
	// Stops tracing syscalls if true
	TracingStatus uint32
}

var version = "test"

func main() {

	functionName := flag.String("fn", "", "Name of the function to trace (mandatory)")
	outputFile := flag.String("o", "", "Output file to store the result")
	commandOutput := flag.Bool("co", false, "Print command output")
	// define usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options] [command]\n", path.Base(os.Args[0]))
		fmt.Printf("\nOptions:\n")
		flag.PrintDefaults()
		fmt.Printf("\nversion: %s\n", version)
	}

	flag.Parse()

	if !isRunningAsRoot() {
		fmt.Println("Not enough privileges to run the program")
		os.Exit(1)
	}

	// Check if the -f flag is provided and has a value
	if *functionName == "" {
		fmt.Println("Error: -fn flag is mandatory. Please provide the name of the function to trace.")
		os.Exit(1)
	}

	// Get the remaining arguments as the command to execute
	command := flag.Args()
	// Check if there are any arguments after the -f flag
	if len(command) == 0 {
		fmt.Println("Error: Command to execute is mandatory. Please provide the command.")
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open an ELF binary and read its symbols.
	ex, err := link.OpenExecutable(command[0])
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	// attach "uprobe/enter_function"
	upEnter, err := ex.Uprobe(*functionName, objs.UprobeEnterFunction, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	defer upEnter.Close()

	// for each RET instruction, attach a "uprobe/exit_function"
	functionRetOffsets, err := getFunctionRetOffsets(command[0], *functionName)
	for _, retOffset := range functionRetOffsets {
		upExit, err := ex.Uprobe(*functionName, objs.UprobeEnterFunction, &link.UprobeOptions{
			Offset: retOffset,
		})
		if err != nil {
			log.Fatal(err)
		}
		defer upExit.Close()
	}

	// attach "tracepoint/raw_syscalls/sys_enter"
	tpSysEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TracepointRawSysEnter, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tpSysEnter.Close()

	// open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	// run command that we want to trace
	go func() {
		cmd := exec.Command(command[0], command[1:]...)
		outErr, _ := cmd.CombinedOutput()
		if *commandOutput {
			fmt.Printf("%s\n", outErr)
		}
		defer cmd.Wait()
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		// wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	var syscalls []uint32
	executionStarted := false

	var e event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}
		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("failed to decode received data %q: %s\n", record, err)
			continue
		}
		switch e.TracingStatus {
		case 1:
			fmt.Fprintln(os.Stdout, "[+] start tracing")
			executionStarted = true
		case 2:
			fmt.Fprintln(os.Stdout, "[+] stop tracing")
			executionStarted = false

			// write to file or stdout depending on the flags passed
			if *outputFile != "" {
				file, _ := createFile(outputFile)
				defer file.Close()
				printSyscalls(file, syscalls)
			} else {
				printSyscalls(os.Stdout, syscalls)
			}

			// send an interrupt to gracefuly shutdown the program
			p, _ := os.FindProcess(os.Getpid())
			p.Signal(os.Interrupt)
		default:
			if executionStarted {
				syscalls = append(syscalls, e.SyscallID)
			}
		}
	}
}
