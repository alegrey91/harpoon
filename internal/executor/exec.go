package executor

import (
	"fmt"
	"os/exec"
	"sync"
)

// Run execute the command and wait for its end.
// The cmdOutput argument is used to print the command output.
func Run(cmd []string, cmdOutput bool, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
	}()

	command := exec.Command(cmd[0], cmd[1:]...)
	output, _ := command.CombinedOutput()
	if cmdOutput {
		fmt.Println("----- BEGIN OF COMMAND OUTPUT -----")
		fmt.Printf("%s", output)
		fmt.Println("------ END OF COMMAND OUTPUT ------")
	}

	command.Wait()
}
