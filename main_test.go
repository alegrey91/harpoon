package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestHarpoon(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "tests",
		//Cmds:                customCommands(),
		RequireExplicitExec: true,
		Setup: func(env *testscript.Env) error {
			// copy test cases into test env
			testCasesSourceDir := filepath.Join("tests", "testcases")
			testCasesDestDir := filepath.Join(env.WorkDir, "testcases")
			err := copyDir(testCasesSourceDir, testCasesDestDir)
			if err != nil {
				return err
			}

			env.Setenv("GOCOVERDIR", "/tmp/integration")
			return nil
		},
	})
}

// copyDir copies the contents of src to dst
func copyDir(src string, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			err = copyDir(srcPath, dstPath)
			if err != nil {
				return err
			}
			continue
		}

		data, err := os.ReadFile(srcPath)
		if err != nil {
			return err
		}

		err = os.WriteFile(dstPath, data, 0644)
		if err != nil {
			return err
		}
	}

	return nil
}
