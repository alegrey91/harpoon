package metadata

import "fmt"

type SymbolsList struct {
	SymbolsOrigins []SymbolsOrigin
}

func NewSymbolsList() *SymbolsList {
	return &SymbolsList{}
}

func (sl *SymbolsList) Add(so *SymbolsOrigin) {
	sl.SymbolsOrigins = append(sl.SymbolsOrigins, *so)
}

func (sl *SymbolsList) String() string {
	output := "---\n"
	output += "symbolsOrigins:\n"
	for _, symbolsOrigin := range sl.SymbolsOrigins {
		output += fmt.Sprintf("  - %s:\n", symbolsOrigin.TestBinaryPath)
		output += "    symbols:\n"
		for _, symbol := range symbolsOrigin.Symbols {
			output += fmt.Sprintf("    - %s\n", symbol)
		}
	}
	return output
}

type SymbolsOrigin struct {
	TestBinaryPath string
	Symbols        []string
}

func NewSymbolsOrigin(testBinPath string) *SymbolsOrigin {
	return &SymbolsOrigin{
		TestBinaryPath: testBinPath,
	}
}

func (so *SymbolsOrigin) IsEmpty() bool {
	return len(so.Symbols) == 0
}

func (so *SymbolsOrigin) Add(symbol string) {
	so.Symbols = append(so.Symbols, symbol)
}
