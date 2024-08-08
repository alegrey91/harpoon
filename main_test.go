package main

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestHarpoon(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "tests",
		//Cmds:                customCommands(),
		RequireExplicitExec: true,
		Setup: func(env *testscript.Env) error {
			env.Setenv("GOCOVERDIR", "/tmp/integration")
			return nil
		},
	})
}
