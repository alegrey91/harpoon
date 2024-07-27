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

	meta "github.com/alegrey91/harpoon/internal/metadata"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

var (
	harpoonFile string
)

type AnalysisReport struct {
}

// huntCmd represents the create args
var huntCmd = &cobra.Command{
	Use:   "hunt",
	Short: "Hunt is like capture but gets a list of functions to be traced",
	Long: `
`,
	Example: "  harpoon hunt --file .harpoon.yaml",
	Run: func(cmd *cobra.Command, args []string) {
		file, err := os.Open(harpoonFile)
		if err != nil {
			fmt.Printf("failed to open %s: %v\n", harpoonFile, err)
			return
		}
		defer file.Close()

		byteValue, err := io.ReadAll(file)
		if err != nil {
			fmt.Printf("Failed to read file: %s", err)
		}

		// Unmarshal the JSON data into the struct
		var analysisReport meta.SymbolsList
		if err := yaml.Unmarshal(byteValue, &analysisReport); err != nil {
			fmt.Printf("Failed to unmarshal YAML: %v", err)
		}
		//fmt.Println(analysisReport)

		for _, symbolsOrigins := range analysisReport.SymbolsOrigins {
			fmt.Println(symbolsOrigins)
		}
	},
}

func init() {
	rootCmd.AddCommand(huntCmd)

	huntCmd.Flags().StringVarP(&harpoonFile, "file", "f", ".harpoon.yaml", "File with the result of analysis")
}
