/*
Copyright © 2024 Alessio Greggi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

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
	"github.com/alegrey91/harpoon/internal/elfreader"
	embedded "github.com/alegrey91/harpoon/internal/embeddable"
	"github.com/alegrey91/harpoon/internal/executor"
	syscallsw "github.com/alegrey91/harpoon/internal/syscallswriter"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/spf13/cobra"
)

type event struct {
	SyscallID uint32
}

var functionSymbols string
var commandOutput bool
var libbpfOutput bool
var save bool
var directory string

var bpfConfigMap = "config_map"
var bpfEventsMap = "events"
var uprobeEnterFunc = "enter_function"
var uprobeExitFunc = "exit_function"
var tracepointFunc = "trace_syscall"
var tracepointCategory = "raw_syscalls"
var tracepointName = "sys_enter"

// captureCmd represents the create args
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture system calls from user-space defined functions.",
	Long: `Capture gives you the ability of tracing system calls
by passing the function name symbol and the binary args.
`,
	Example: "  harpoon -f main.doSomething ./command arg1 arg2 ...",
	Run: func(cmd *cobra.Command, args []string) {
		functionSymbolList := strings.Split(functionSymbols, ",")

		if !libbpfOutput {
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
			fmt.Printf("error loading BPF object file: %v\n", err)
			os.Exit(-1)
		}
		defer bpfModule.Close()

		/*
			HashMap used for passing various configuration
			from user-space to kernel-space.
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
		enterLinks := make([]*bpf.BPFLink, len(functionSymbolList))
		exitLinks := make([][]*bpf.BPFLink, len(functionSymbolList))
		for id, functionSymbol := range functionSymbolList {
			offset, err := helpers.SymbolToOffset(args[0], functionSymbol)
			if err != nil {
				fmt.Printf("error finding function (%s) offset: %v\n", functionSymbol, err)
				os.Exit(-1)
			}
			enterLink, err := enterFuncProbe.AttachUprobe(-1, args[0], offset)
			if err != nil {
				fmt.Printf("error attaching uprobe at function (%s) offset: %d, error: %v\n", functionSymbol, offset, err)
				os.Exit(-1)
			}
			enterLinks = append(enterLinks, enterLink)

			/*
				Since the uretprobes doesn't work well with Go binaries,
				we are going to attach a uprobe ∀ RET instruction withing the
				traced function.
			*/
			functionRetOffsets, err := elfreader.GetFunctionRetOffsets(args[0], functionSymbol)
			for _, offsetRet := range functionRetOffsets {
				exitLink, err := exitFuncProbe.AttachUprobe(-1, args[0], offset+uint32(offsetRet))
				if err != nil {
					fmt.Printf("error attaching uprobe at function (%s) RET: %d, error: %v\n", functionSymbol, offset+uint32(offsetRet), err)
					os.Exit(-1)
				}
				exitLinks[id] = append(exitLinks[id], exitLink)
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
		baseargs := filepath.Base(args[0])
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
			fmt.Println("error initializing map (%s) with PerfBuffer: %v\n", bpfEventsMap, err)
			os.Exit(-1)
		}

		// run args that we want to trace
		var wg sync.WaitGroup
		wg.Add(1)
		go executor.Run(args, commandOutput, &wg)

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
		if save {
			fileName := archiver.Convert(functionSymbolList[0])
			err := os.Mkdir(directory, 0766)
			if err != nil {
				fmt.Printf("error creating directory: %v\n", err)
				os.Exit(-1)
			}
			file, err := os.Create(path.Join(directory, fileName))
			if err != nil {
				fmt.Printf("error creating file %s: %v\n", file, err)
				os.Exit(-1)
			}
			defer file.Close()

			if err := file.Chmod(0744); err != nil {
				fmt.Printf("error setting permissions to %s: %v\n", file, err)
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
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)

	captureCmd.Flags().StringVarP(&functionSymbols, "functions", "f", "", "Name of the function symbols to be traced")
	captureCmd.MarkFlagRequired("functions")

	captureCmd.Flags().BoolVarP(&commandOutput, "include-cmd-output", "c", false, "Include the executed command output")

	captureCmd.Flags().BoolVarP(&libbpfOutput, "include-libbpf-output", "l", false, "Include the libbpf output")

	captureCmd.Flags().BoolVarP(&save, "save", "S", false, "Save output to a file")
	captureCmd.Flags().StringVarP(&directory, "directory", "D", "", "Directory to use to store saved files")
	captureCmd.MarkFlagsRequiredTogether("save", "directory")
}
