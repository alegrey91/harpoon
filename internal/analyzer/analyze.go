package analyzer

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

func isTestFunction(name string) bool {
	return strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Test_")
}

func getTestedFunctionName(testName string) string {
	if strings.HasPrefix(testName, "Test_") {
		return testName[5:] // Remove "Test_"
	}
	return testName[4:] // Remove "Test"
}

func AnalyzeTestFile(moduleName, path string) ([]string, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		return []string{}, fmt.Errorf("failed to parse %s: %v", path, err)
	}

	// retrieve the last directory from the module name
	lastDirectory := filepath.Base(filepath.Clean(moduleName))
	// remove the file from the directory
	dir, _ := filepath.Split(path)
	// remove the / char from the end of the path
	dir = strings.TrimSuffix(dir, "/")
	// remove all the ../ from the path
	dir = strings.ReplaceAll(dir, "../", "")
	// remove the base directory since it is already present in the module name
	dir = strings.TrimPrefix(dir, lastDirectory+"/")

	var functionList []string
	for _, decl := range node.Decls {
		if fn, isFn := decl.(*ast.FuncDecl); isFn {
			if isTestFunction(fn.Name.Name) {
				testedFunction := getTestedFunctionName(fn.Name.Name)
				functionList = append(functionList, fmt.Sprintf("%s/%s.%s", moduleName, dir, testedFunction))
			}
		}
	}
	return functionList, nil
}

func GetModuleName(goModFile *os.File) (string, error) {
	scanner := bufio.NewScanner(goModFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading %s: %v", goModFile.Name(), err)
	}
	return "", fmt.Errorf("unable to find module in file: %s", goModFile.Name())
}

func CheckFunctionExists(functionName string, goFile *os.File) (bool, error) {
	searchString := functionName + "("

	scanner := bufio.NewScanner(goFile)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, searchString) {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("error reading %s: %v", goFile.Name(), err)
	}
	return false, fmt.Errorf("unable to find function \"%s\" in %s file", functionName, goFile.Name())
}

// ExtractFunctionName extracts the function name from the given string.
func ExtractFunctionName(path string) string {
	// Split the string by the '.' character
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return ""
	}
	// Return the last part of the split result
	return parts[len(parts)-1]
}
