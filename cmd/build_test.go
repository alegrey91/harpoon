package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildProfileCreateError(t *testing.T) {
	oldDirectory, oldSave, oldName := inputDirectory, saveProfile, profileName
	defer func() {
		inputDirectory, saveProfile, profileName = oldDirectory, oldSave, oldName
	}()
	inputDirectory = t.TempDir()
	saveProfile = true
	profileName = filepath.Join(t.TempDir(), "missing", "seccomp.json")
	err := buildCmd.RunE(buildCmd, nil)
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("expected a wrapped file creation error, got %v", err)
	}
	if !strings.Contains(err.Error(), profileName) {
		t.Fatalf("error does not identify requested profile %q: %v", profileName, err)
	}
}
