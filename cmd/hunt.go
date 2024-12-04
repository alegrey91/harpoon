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
	"io"
	"os"

	"github.com/alegrey91/harpoon/internal/ebpf/probesfacade/captor"
	meta "github.com/alegrey91/harpoon/internal/metadata"
	"github.com/alegrey91/harpoon/internal/writer"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

var (
	harpoonFile string
)

// huntCmd represents the create args
var huntCmd = &cobra.Command{
	Use:   "hunt",
	Short: "Hunt is like capture but gets a list of functions to be traced",
	Long: `
`,
	Example: "  harpoon hunt --file harpoon-report.yml",
	RunE: func(cmd *cobra.Command, args []string) error {
		file, err := os.Open(harpoonFile)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", harpoonFile, err)
		}
		defer file.Close()

		byteValue, err := io.ReadAll(file)
		if err != nil {
			return fmt.Errorf("failed to read file %q: %w", file.Name(), err)
		}

		// Unmarshal the JSON data into the struct
		var analysisReport meta.SymbolsList
		if err := yaml.Unmarshal(byteValue, &analysisReport); err != nil {
			return fmt.Errorf("failed to unmarshal YAML in %q: %w", harpoonFile, err)
		}
		//fmt.Println(analysisReport)

		for _, symbolsOrigins := range analysisReport.SymbolsOrigins {
			fmt.Println("test binary:", symbolsOrigins.TestBinaryPath)
			fmt.Println("symbols:", symbolsOrigins.Symbols)

			// command builder
			var captureArgs []string
			captureArgs = append(captureArgs, symbolsOrigins.TestBinaryPath)
			opts := captor.CaptureOptions{
				CommandOutput: commandOutput,
				LibbpfOutput:  libbpfOutput,
				Interval:      0,
			}

			saveOpts := writer.WriteOptions{
				Save:      save,
				Directory: directory,
			}

			for _, functionSymbol := range symbolsOrigins.Symbols {
				syscalls, err := captor.Capture(functionSymbol, captureArgs, opts, nil)
				if err != nil {
					fmt.Printf("error capturing syscall: %v", err)
				}

				if err = writer.Write(syscalls, functionSymbol, saveOpts); err != nil {
					return fmt.Errorf("error writing seccomp profile: %w", err)
				}
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(huntCmd)

	huntCmd.Flags().StringVarP(&harpoonFile, "file", "F", "harpoon-report.yml", "File with the result of analysis")
	huntCmd.MarkFlagRequired("file")

	huntCmd.Flags().BoolVarP(&commandOutput, "include-cmd-stdout", "c", false, "Include the executed command output")
	huntCmd.Flags().BoolVarP(&commandError, "include-cmd-stderr", "e", false, "Include the executed command error")

	huntCmd.Flags().BoolVarP(&libbpfOutput, "include-libbpf-output", "l", false, "Include the libbpf output")

	huntCmd.Flags().BoolVarP(&save, "save", "S", false, "Save output to a file")
	huntCmd.Flags().StringVarP(&directory, "directory", "D", "", "Directory to use to store saved files")
	huntCmd.MarkFlagsRequiredTogether("save", "directory")
}
