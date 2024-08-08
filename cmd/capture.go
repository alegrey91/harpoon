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
var libbpfOutput bool
var save bool
var directory string

// captureCmd represents the create args
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture system calls from user-space defined functions.",
	Long: `Capture gives you the ability of tracing system calls
by passing the function name symbol and the binary args.
`,
	Example: "  harpoon -f main.doSomething ./command arg1 arg2 ...",
	RunE: func(cmd *cobra.Command, args []string) error {

		functionSymbolList := strings.Split(functionSymbols, ",")

		captureOpts := captor.CaptureOptions{
			CommandOutput: commandOutput,
			LibbpfOutput:  libbpfOutput,
		}
		for _, functionSymbol := range functionSymbolList {
			syscalls, err := captor.Capture(functionSymbol, args, captureOpts)
			if err != nil {
				return fmt.Errorf("error capturing syscall: %w", err)
			}

			saveOpts := writer.WriteOptions{
				Save:      save,
				Directory: directory,
			}
			if err := writer.Write(syscalls, functionSymbols, saveOpts); err != nil {
				return fmt.Errorf("error writing syscalls for symbol %s: %w", functionSymbol, err)
			}
		}
		return nil
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
