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
	"fmt"
	"strings"

	"github.com/alegrey91/harpoon/internal/ebpf/probesfacade/captor"
	"github.com/alegrey91/harpoon/internal/writer"
	"github.com/spf13/cobra"
)

var functionSymbols string
var commandOutput bool
var commandError bool
var libbpfOutput bool
var save bool
var directory string
var filename string
var dumpInterval int

// captureCmd represents the create args
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture system calls from user-space defined functions.",
	Long: `Capture gives you the ability of tracing system calls
by passing the function name symbol and the binary args.
`,
	Example: "  harpoon -f main.doSomething -- ./command arg1 arg2 ...",
	RunE: func(cmd *cobra.Command, args []string) error {

		functionSymbolList := strings.Split(functionSymbols, ",")

		captureOpts := captor.CaptureOptions{
			CommandOutput: commandOutput,
			LibbpfOutput:  libbpfOutput,
			Interval:      dumpInterval,
		}

		saveOpts := writer.WriteOptions{
			Save:      save,
			FileName:  filename,
			Directory: directory,
		}

		for _, functionSymbol := range functionSymbolList {
			resultChan := make(chan []uint32)

			go func() {
				defer close(resultChan)
				if captureOpts.Interval == 0 {
					// this will get the result at the end of the program execution
					syscalls, err := captor.Capture(functionSymbol, args, captureOpts, nil)
					if err != nil {
						fmt.Printf("error capturing syscall: %v\n", err)
						return
					}
					resultChan <- syscalls
				} else {
					// this will get incremental results
					if _, err := captor.Capture(functionSymbol, args, captureOpts, resultChan); err != nil {
						fmt.Printf("error capturing syscall: %v\n", err)
						return
					}
				}
			}()

			for syscalls := range resultChan {
				if err := writer.Write(syscalls, functionSymbols, saveOpts); err != nil {
					return fmt.Errorf("error writing syscalls for symbol %s: %w", functionSymbol, err)
				}
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)

	captureCmd.Flags().StringVarP(&functionSymbols, "functions", "f", "", "Name of the function symbols to be traced")
	captureCmd.MarkFlagRequired("functions")

	captureCmd.Flags().BoolVarP(&commandOutput, "include-cmd-stdout", "c", false, "Include the executed command output")
	captureCmd.Flags().BoolVarP(&commandError, "include-cmd-stderr", "e", false, "Include the executed command error")
	captureCmd.Flags().BoolVarP(&libbpfOutput, "include-libbpf-output", "l", false, "Include the libbpf output")

	captureCmd.Flags().BoolVarP(&save, "save", "S", false, "Save output to a file")
	captureCmd.Flags().StringVarP(&filename, "name", "n", "", "Specify a name for saved output")
	captureCmd.Flags().StringVarP(&directory, "directory", "D", "", "Store saved files in a directory")
	captureCmd.Flags().IntVarP(&dumpInterval, "dump-interval", "i", 0, "Dump results every interval of time")
	captureCmd.MarkFlagsRequiredTogether("save", "directory")
}
