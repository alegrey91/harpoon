/*
Copyright © 2026 Alessio Greggi

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
	"sync"

	"github.com/alegrey91/harpoon/internal/executor"
	"github.com/alegrey91/harpoon/internal/seccomputils"
	"github.com/spf13/cobra"
)

var (
	sandboxProfile       string
	sandboxEnvVars       []string
	sandboxCommandOutput bool
	sandboxCommandError  bool
)

var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Run a command in a sandboxed environment defined by a Seccomp profile.",
	Long: `
`,
	Example:       "  harpoon sandbox --profile path/to/profile.json -- ./command arg1 arg2 ...",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("no command provided: please specify the program to run after '--'")
		}

		// Load the seccomp profile from disk.
		profile, err := seccomputils.LoadProfile(sandboxProfile)
		if err != nil {
			return fmt.Errorf("error loading seccomp profile: %w", err)
		}

		// Apply the seccomp filter to the current process before launching
		// the child. The filter is inherited by child processes on exec.
		if err := seccomputils.ApplyFilter(profile); err != nil {
			return fmt.Errorf("error applying seccomp filter: %w", err)
		}

		// Set up channels to collect stdout/stderr from the executed program.
		cmdStdoutCh := make(chan string)
		cmdStderrCh := make(chan string)
		var wg sync.WaitGroup
		wg.Add(1)

		// Run the program using the shared executor.
		go executor.Run(
			args,
			sandboxEnvVars,
			sandboxCommandOutput,
			sandboxCommandError,
			&wg,
			cmdStdoutCh,
			cmdStderrCh,
		)

		// Drain stdout and stderr channels while the command is running.
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case line, ok := <-cmdStdoutCh:
					if !ok {
						cmdStdoutCh = nil
					} else {
						fmt.Println(line)
					}
				case line, ok := <-cmdStderrCh:
					if !ok {
						cmdStderrCh = nil
					} else {
						fmt.Fprintln(cmd.ErrOrStderr(), line)
					}
				}
				if cmdStdoutCh == nil && cmdStderrCh == nil {
					return
				}
			}
		}()

		// Wait for the command to finish, then close the I/O channels and
		// wait for the drainer goroutine to exit.
		wg.Wait()
		close(cmdStdoutCh)
		close(cmdStderrCh)
		<-done
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sandboxCmd)

	sandboxCmd.Flags().StringVarP(&sandboxProfile, "profile", "p", "", "Path to the Seccomp profile")
	sandboxCmd.MarkFlagRequired("profile")

	sandboxCmd.Flags().StringSliceVarP(&sandboxEnvVars, "env-var", "E", []string{}, "Environment variable to be passed to the executed command")

	sandboxCmd.Flags().BoolVarP(&sandboxCommandOutput, "include-cmd-stdout", "c", false, "Include the executed command output")
	sandboxCmd.Flags().BoolVarP(&sandboxCommandError, "include-cmd-stderr", "e", false, "Include the executed command error")
}
