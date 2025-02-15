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
	"slices"
	"sort"

	seccomp "github.com/alegrey91/harpoon/internal/seccomputils"
	"github.com/alegrey91/harpoon/internal/syscallutils"
	"github.com/spf13/cobra"
)

var (
	inputDirectory      string
	saveProfile         bool
	profileName         = "seccomp.json"
	syscallSets         []string
	syscallVariants     bool
	dynamicBin          = "dynamic"
	staticBin           = "static"
	dockerEnv           = "docker"
	expectedSyscallSets = []string{dynamicBin, staticBin, dockerEnv}
)

// buildCmd represents the create args
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "build collects system calls from harpoon generated files and create a Seccomp profile with them",
	Long: `
`,
	Example:       "  harpoon build --add-syscall-sets=dynamic,docker --directory=/tmp/result",
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// validate syscall sets have expected values
		if cmd.Flags().Changed("add-syscall-sets") {
			return validateSyscallSets(syscallSets, expectedSyscallSets)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		files, err := os.ReadDir(inputDirectory)
		if err != nil {
			return fmt.Errorf("error reading dir content: %w", err)
		}

		var syscallList = make(map[string]int)
		// add minimum set of syscalls for dynamically linked go binaries
		if slices.Contains(syscallSets, dynamicBin) {
			for _, syscall := range syscallutils.MinDynamicGoSyscallSet {
				if seccomp.IsValidSyscall(syscall) {
					syscallList[syscall]++
				}
			}
		}
		// add minimum set of syscalls for statically linked go binaries
		if slices.Contains(syscallSets, staticBin) {
			for _, syscall := range syscallutils.MinStaticGoSyscallSet {
				if seccomp.IsValidSyscall(syscall) {
					syscallList[syscall]++
				}
			}
		}
		// add minimum set of syscalls for docker
		if slices.Contains(syscallSets, dockerEnv) {
			for _, syscall := range syscallutils.MinDockerSyscallSet {
				if seccomp.IsValidSyscall(syscall) {
					syscallList[syscall]++
				}
			}
		}

		syscalls := make([]string, 0)
		// collect syscalls from files
		for _, fileObj := range files {
			file, err := os.Open(filepath.Join(inputDirectory, fileObj.Name()))
			if err != nil {
				return fmt.Errorf("error opening file %q: %w", fileObj.Name(), err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				syscall := scanner.Text()
				if !seccomp.IsValidSyscall(syscall) {
					continue
				}
				if syscallVariants {
					variants := syscallutils.GetVariants(syscall)
					if len(variants) > 0 {
						for _, v := range variants {
							syscallList[v]++
						}
						// once all the variants have been added to the list
						// we can skip the adding of the original syscall
						// since it's already in the list.
						continue
					}
				}
				syscallList[syscall]++
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

	buildCmd.Flags().StringSliceVarP(&syscallSets, "add-syscall-sets", "s", []string{}, fmt.Sprintf("Add syscall sets to the final list (available sets: %s, %s, %s)", dynamicBin, staticBin, dockerEnv))
	buildCmd.Flags().BoolVarP(&syscallVariants, "add-syscall-variants", "V", false, "Add syscall variants to the final list")
	buildCmd.Flags().BoolVarP(&saveProfile, "save", "S", false, "Save profile to a file")
	buildCmd.Flags().StringVarP(&profileName, "name", "n", profileName, "Specify a name for the seccomp profile")
}

// validateSyscallsSets ensure all the passed values are correct
func validateSyscallSets(sets, expectedSets []string) error {
	for _, set := range sets {
		if !slices.Contains(expectedSets, set) {
			return fmt.Errorf("unexpected set passed as argument: %s", set)
		}
	}
	return nil
}
