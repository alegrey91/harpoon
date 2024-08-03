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
	Run: func(cmd *cobra.Command, args []string) {
		files, err := os.ReadDir(inputDirectory)
		if err != nil {
			fmt.Printf("error reading dir content: %v", err)
			return
		}

		syscalls := make([]string, 0)
		for _, fileObj := range files {
			//fmt.Println("[" + fileObj.Name() + "]")

			file, err := os.Open(inputDirectory + "/" + fileObj.Name())
			if err != nil {
				fmt.Printf("error opening file %s: %v", file.Name(), err)
				return
			}
			defer file.Close()

			// collect system calls from file
			var syscallList = make(map[string]int)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				syscall := scanner.Text()
				syscallList[string(syscall)]++
			}

			// convert map to list of string
			for value := range syscallList {
				syscalls = append(syscalls, value)
			}
		}

		profile, err := seccomp.BuildProfile(syscalls)
		if err != nil {
			fmt.Printf("error building seccomp profile: %v", err)
		}

		if saveProfile {
			profileFile, err := os.Create(profileName)
			if err != nil {
				fmt.Printf("error creating seccomp file %s: %v\n", profileFile.Name(), err)
				return
			}
			defer profileFile.Close()

			if err := profileFile.Chmod(0644); err != nil {
				fmt.Printf("error setting permissions to %s: %v\n", profileFile.Name(), err)
				return
			}
			// write to file
			fmt.Fprintln(profileFile, profile)
		} else {
			fmt.Println(profile)
		}
	},
}

func init() {
	rootCmd.AddCommand(buildCmd)

	buildCmd.Flags().StringVarP(&inputDirectory, "directory", "D", "", "Directory containing harpoon's files")
	buildCmd.MarkFlagRequired("directory")

	buildCmd.Flags().BoolVarP(&saveProfile, "save-profile", "s", false, "Save profile to a file")
	buildCmd.Flags().StringVarP(&profileName, "name", "n", profileName, "Save profile to a file")
}
