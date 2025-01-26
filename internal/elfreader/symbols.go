package elfreader

import (
	"debug/elf"
	"fmt"
	"regexp"
	"strings"
)

type ElfReader struct {
	file *elf.File
}

// NewElfReader opens an ELF file and returns the ElfReader struct.
func NewElfReader(filePath string) *ElfReader {
	elfFile, err := elf.Open(filePath)
	if err != nil {
		fmt.Println("error: %w", err)
	}
	return &ElfReader{
		file: elfFile,
	}
}

// Close closes the ElfReader file.
func (e *ElfReader) Close() {
	e.file.Close()
}

// FunctionSymbols returns the list of function symbols within the ELF file.
func (e *ElfReader) FunctionSymbols(pattern string) ([]string, error) {
	symbols, err := e.file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("error getting symbols: %v", err)
	}

	var symbolsList []string
	for _, symb := range symbols {
		// filter only function symbols
		if !(elf.ST_TYPE(symb.Info) == elf.STT_FUNC) {
			continue
		}
		// filter for package related symbols
		if !strings.Contains(symb.Name, pattern) {
			continue
		}
		// filter out Test functions
		if isTestFunction(symb.Name) {
			continue
		}
		// filter out goroutines
		if isGoroutine(symb.Name) {
			continue
		}
		// filter out type struct
		if strings.HasPrefix(symb.Name, "type:") {
			continue
		}
		symbolsList = append(symbolsList, symb.Name)
	}
	return symbolsList, nil
}

// isGoroutine detects if the symbol passed as argument is a goroutine function.
func isGoroutine(s string) bool {
	// Regular expression to match ".func" followed by one or more digits
	re := regexp.MustCompile(`\.func\d+$`)
	return re.MatchString(s)
}

// isTestFunction detects if the symbol passed as argument is a Test function.
func isTestFunction(s string) bool {
	// Regular expression to check for valid Test suffix patterns
	re := regexp.MustCompile(`\.Test[\w.]*$`)
	return re.MatchString(s)
}
