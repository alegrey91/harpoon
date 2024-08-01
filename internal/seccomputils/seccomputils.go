package seccomputils

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
)

//go:embed seccomp.tmpl
var SeccompProfileTemplate string

// Data to hold the syscalls
type SeccompContent struct {
	Syscalls []string
}

// sub1 is a helper function to subtract 1 from an integer
func sub1(i int) int {
	return i - 1
}

// BuildProfile builds the seccomp profile from the list of syscalls
func BuildProfile(syscalls []string) (string, error) {
	// Parse the template
	tmpl, err := template.New("seccomp").Funcs(template.FuncMap{
		"sub1": sub1,
	}).Parse(SeccompProfileTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// Prepare the data
	data := SeccompContent{
		Syscalls: syscalls,
	}

	// Execute the template
	var profile bytes.Buffer
	if err := tmpl.Execute(&profile, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return profile.String(), nil
}
