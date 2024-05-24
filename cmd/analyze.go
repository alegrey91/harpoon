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
	"path/filepath"
	"strings"

	"github.com/alegrey91/harpoon/internal/analyzer"
	"github.com/alegrey91/harpoon/internal/executor"
	"github.com/alegrey91/harpoon/internal/metadata"
	"github.com/spf13/cobra"
)

var excludedPaths []string
var exclude string
var saveAnalysis bool

// captureCmd represents the create args
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze infers the symbols of functions that are tested by unit-tests",
	Long: `
`,
	Example: "  harpoon analyze --exclude vendor/ /path/to/repo/",
	Run: func(cmd *cobra.Command, args []string) {
		if exclude != "" {
			excludedPaths = strings.Split(exclude, ",")
		}

		file, err := os.Open("go.mod")
		if err != nil {
			fmt.Printf("failed to open %s: %v\n", "go.mod", err)
			return
		}
		defer file.Close()

		moduleName, err := analyzer.GetModuleName(file)
		if err != nil {
			fmt.Println("module name not found in go.mod")
			return
		}

		symbolsList := metadata.NewSymbolsList()

		// Walk the directory to find all _test.go files
		err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("error walking filesystem: %v", err)
			}
			fmt.Printf("analyzing file: %s\n", path)

			if shouldSkipPath(path) {
				fmt.Println("file was skipped")
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if !info.IsDir() && strings.HasSuffix(info.Name(), "_test.go") {
				fmt.Println("analyzing symbols")
				symbolNames, err := analyzer.AnalyzeTestFile(moduleName, path)
				if err != nil {
					return fmt.Errorf("unable to infer symbols from test file: %s", path)
				}

				fmt.Println("building test binary")
				// build test binary
				os.Mkdir(".harpoon", 0644)
				pkgPath := getPackagePath(path)
				testFile := filepath.Base(path)
				testFile = strings.ReplaceAll(testFile, "_test.go", ".test")
				_, err = executor.Build(pkgPath, ".harpoon/"+testFile)
				if err != nil {
					return fmt.Errorf("failed to build test file: %v", err)
				}

				symbolsOrig := metadata.NewSymbolsOrigin(".harpoon/" + testFile)

				fmt.Println("test: .harpoon/" + testFile)
				for _, symbol := range symbolNames {
					// retrieve tested function from symbol
					parts := strings.Split(symbol, ".")
					testedFunction := parts[len(parts)-1]

					// retrieve source file from _test.go file
					sourceFile := strings.ReplaceAll(path, "_test", "")
					file, err := os.Open(sourceFile)
					if err != nil {
						return fmt.Errorf("failed to open %s: %v", sourceFile, err)
					}
					defer file.Close()

					functionExists, err := analyzer.CheckFunctionExists(testedFunction, file)
					if !functionExists {
						fmt.Printf("function not found: %v\n", err)
						continue
					}
					symbolsOrig.Add(symbol)
				}
				if !symbolsOrig.IsEmpty() {
					symbolsList.Add(symbolsOrig)
				}
			}
			return nil
		})

		if err != nil {
			fmt.Printf("error walking the path: %v\n", err)
		}

		// store to file
		file, err = os.Create(".harpoon.yml")
		if err != nil {
			fmt.Printf("failed to create symbols list file")
			return
		}
		mw := io.Writer(file)
		fmt.Fprintln(mw, symbolsList.String())
		fmt.Println("file .harpoon.yml is ready")
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().StringVarP(&exclude, "exclude", "e", "", "Skip directories specified in the comma separated list")
	analyzeCmd.Flags().BoolVarP(&saveAnalysis, "save", "s", false, "Save analysis in a file")
}

func shouldSkipPath(path string) bool {
	for _, excludedPath := range excludedPaths {
		if strings.Contains(path, excludedPath) {
			return true
		}
	}
	return false
}

func getPackagePath(inputPath string) string {
	// Normalize the path
	normalizedPath := filepath.Clean(inputPath)

	// Get the directory part of the path if it's a file path
	dirPath := normalizedPath
	if !strings.HasSuffix(inputPath, "/") {
		dirPath = filepath.Dir(normalizedPath)
	}

	// Ensure the path starts with "./"
	if !strings.HasPrefix(dirPath, ".") {
		dirPath = "./" + dirPath
	}

	// Remove any leading "../" or "./" parts not relevant to the target directory structure
	// Adjust this according to your specific requirements
	dirPath = strings.TrimPrefix(dirPath, "../")
	dirPath = strings.TrimPrefix(dirPath, "./")

	// Add "./" at the start again if necessary
	dirPath = "./" + dirPath

	return dirPath
}
