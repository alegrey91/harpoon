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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	seccomp "github.com/alegrey91/harpoon/internal/seccomputils"
	"github.com/spf13/cobra"
)

var (
	inputDirectory string
	saveProfile    bool
	profileName    = "seccomp.json"
)

// buildCmd represents the create args
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "build collects system calls from harpoon generated files and create a Seccomp profile with them",
	Long: `
`,
	Example: "  harpoon build",
	RunE: func(cmd *cobra.Command, args []string) error {
		files, err := os.ReadDir(inputDirectory)
		if err != nil {
			return fmt.Errorf("error reading dir content: %w", err)
		}

		syscalls := make([]string, 0)
		var syscallList = make(map[string]int)
		for _, fileObj := range files {
			file, err := os.Open(filepath.Join(inputDirectory, fileObj.Name()))
			if err != nil {
				return fmt.Errorf("error opening file %q: %w", fileObj.Name(), err)
			}
			defer file.Close()

			// collect system calls from file
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				syscall := scanner.Text()
				if seccomp.IsValidSyscall(syscall) {
					syscallList[string(syscall)]++
				}
			}
		}

		// convert map to list of string
		for value := range syscallList {
			syscalls = append(syscalls, value)
		}
		sort.Strings(syscalls)

		profile, err := seccomp.BuildProfile(syscalls)
		if err != nil {
			return fmt.Errorf("error building seccomp profile: %w", err)
		}

		if saveProfile {
			profileFile, err := os.Create(profileName)
			if err != nil {
				return fmt.Errorf("error creating seccomp file %s: %w", profileFile.Name(), err)
			}
			defer profileFile.Close()

			if err := profileFile.Chmod(0644); err != nil {
				return fmt.Errorf("error setting permissions to %s: %w", profileFile.Name(), err)
			}
			// write to file
			fmt.Fprintln(profileFile, profile)
		} else {
			fmt.Println(profile)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(buildCmd)

	buildCmd.Flags().StringVarP(&inputDirectory, "directory", "D", "", "Directory containing harpoon's metadata files")
	buildCmd.MarkFlagRequired("directory")

	buildCmd.Flags().BoolVarP(&saveProfile, "save", "S", false, "Save profile to a file")
	buildCmd.Flags().StringVarP(&profileName, "name", "n", profileName, "Specify a name for the seccomp profile")
}
