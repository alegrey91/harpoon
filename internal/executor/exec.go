package executor

import (
	"bufio"
	"fmt"
	"os/exec"
	"sync"
)

// Run execute the command and wait for its end.
// The cmdOutput argument is used to print the command output.
func Run(cmd []string, cmdOutput, cmdError bool, wg *sync.WaitGroup, outputCh, errorCh chan<- string) {
	defer func() {
		wg.Done()
	}()

	command := exec.Command(cmd[0], cmd[1:]...)
	stdout, _ := command.StdoutPipe()
	stderr, _ := command.StderrPipe()

	//command.Wait()
	command.Start()

	go func() {
		if cmdOutput {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				outputCh <- scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				outputCh <- fmt.Sprintf("error: %v", err)
			}
		}
		if cmdError {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				errorCh <- scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				errorCh <- fmt.Sprintf("error: %v", err)
			}
		}
	}()

	command.Wait()
	close(outputCh)
	close(errorCh)
}

func Build(packagePath, outputFile string) (string, error) {
	cmd := exec.Command(
		"go",
		"test",
		`-gcflags="-N -l"`,  // disable optimization
		"-c", packagePath, // build test binary
		"-o", outputFile, // save it in a dedicated directory
	)

	stdout, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute build command '%s': %v", cmd.String(), err)
	}

	return string(stdout), nil
}
