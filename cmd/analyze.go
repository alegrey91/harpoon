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
	"github.com/alegrey91/harpoon/internal/archiver"
	"github.com/alegrey91/harpoon/internal/elfreader"
	"github.com/alegrey91/harpoon/internal/executor"
	"github.com/alegrey91/harpoon/internal/metadata"
	"github.com/spf13/cobra"
)

var (
	excludeList        []string
	saveAnalysis       bool
	analysisReportFile = "harpoon-report.yml"
)

// analyzeCmd represents the create args
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze infers the symbols of functions that are tested by unit-tests",
	Long: `
`,
	Example:       "  harpoon analyze --exclude vendor/",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		file, err := os.Open("go.mod")
		if err != nil {
			return fmt.Errorf("failed to open go.mod: %w", err)
		}
		defer file.Close()

		moduleName, err := analyzer.GetModuleName(file)
		if err != nil {
			return fmt.Errorf("error module name not found in go.mod: %w", err)
		}

		symbolsList := metadata.NewSymbolsList()

		// walk the project file systems to find occurrences of _test.go files.
		// when we find a _test.go file, we build the entire test of the package
		// where we found the test.
		// once built, we read the content of the test file to extract the symbols
		// of the functions present in the binary.
		// with all the collected symbols, we verify the presence of their associated function
		// within the _test.go files in the same directory.
		// if some function is found, then we add this to the final report.
		err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("error walking filesystem: %v", err)
			}

			if shouldSkipPath(path) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			fmt.Printf("analyzing file: %s\n", path)

			// we found a _test.go file, so we are going to build it
			// and retrieve its symbols.
			if !info.IsDir() && strings.HasSuffix(info.Name(), "_test.go") {
				// build test binary
				os.Mkdir(directory, 0644)

				// converting pkg where we found tests
				// to a test-bin-file name.
				// eg. ./pkg/v1beta1/ -> __pkg_v1beta1.test
				pkgPath := getPackagePath(path)
				testBinFile := archiver.Convert(pkgPath)
				testBinFile = testBinFile + ".test"
				// this is where we are going to store out test-bin-file.
				testBinPath := filepath.Join(directory, testBinFile)

				fmt.Println("building test binary:", testBinFile)
				_, err = executor.Build(pkgPath, testBinPath)
				if err != nil {
					return fmt.Errorf("failed to build test file: %v", err)
				}

				// retrieving function symbols from ELF file.
				elf, err := elfreader.NewElfReader(testBinPath)
				if err != nil {
					return fmt.Errorf("failed to initialize elf file: %v", err)
				}
				fnSymbols, err := elf.FunctionSymbols(moduleName)
				if err != nil {
					return fmt.Errorf("failed to get function symbols: %v", err)
				}

				symbolsOrig := metadata.NewSymbolsOrigin(testBinPath)

				// for each symbol found in the ELF file,
				// we are going to verify if the related function exists
				// in the _test.go files in the same directory.
				// if not, they will not be included in the report,
				// so we can avoid useless symbols to be traced.
				for _, symbol := range fnSymbols {
					functionName := analyzer.ExtractFunctionName(symbol)
					testFiles, _ := listTestFiles(path)
					for _, testFile := range testFiles {
						tf, err := os.Open(testFile)
						if err != nil {
							fmt.Printf("error opening file: %v\n", err)
							continue
						}
						defer tf.Close()

						exists, _ := analyzer.CheckFunctionExists(functionName, tf)
						if exists {
							//fmt.Printf("function %s exists in file %s\n", functionName, testFile)
							symbolsOrig.Add(symbol)
							break // this will save us some iterations
						}
					}
				}
				// if we've found symbols, then we add the list
				// to the corresponding binary entry.
				// eg:
				// - testBinaryPath: /tmp/artifacts/__pkg_utils.test
				//   symbols:
				//   - github.com/myuser/myproject/pkg/utils.NewUserGroupList
				//   - github.com/myuser/myproject/pkg/utils.(*userGroupList).Find
				if !symbolsOrig.IsEmpty() {
					symbolsList.Add(symbolsOrig)
				}
				return filepath.SkipDir
			}
			return nil
		})

		if err != nil {
			fmt.Printf("error walking the path: %v\n", err)
		}

		// store to file
		if saveAnalysis {
			file, err = os.Create(analysisReportFile)
			if err != nil {
				return fmt.Errorf("failed to create symbols list file: %w", err)
			}
			mw := io.Writer(file)
			_, err := fmt.Fprintln(mw, symbolsList.String())
			if err != nil {
				return fmt.Errorf("error writing into %s: %v", analysisReportFile, err)
			}
			fmt.Printf("file %s is ready\n", analysisReportFile)
		} else {
			fmt.Println(symbolsList.String())
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().StringSliceVarP(&excludeList, "exclude", "e", []string{}, "Exclude directory from analysis")
	analyzeCmd.Flags().BoolVarP(&saveAnalysis, "save", "S", false, "Save analysis result into a file")
	analyzeCmd.Flags().StringVarP(&directory, "directory", "D", ".harpoon", "Store saved files in a directory")
}

func shouldSkipPath(path string) bool {
	for _, excludedPath := range excludeList {
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
	//dirPath = strings.TrimPrefix(inputPath, rootPath)

	// Add "./" at the start again if necessary
	dirPath = "./" + dirPath

	return dirPath
}

// listTestFiles lists all files in the directory that end with "_test.go".
func listTestFiles(directory string) ([]string, error) {
	var testFiles []string

	// Walk through the directory
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err // Handle errors while walking
		}

		// Check if the file ends with "_test.go"
		if !info.IsDir() && strings.HasSuffix(info.Name(), "_test.go") {
			testFiles = append(testFiles, path)
		}
		return nil
	})

	return testFiles, err
}
