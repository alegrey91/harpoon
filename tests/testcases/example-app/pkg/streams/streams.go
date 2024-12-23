package streams

import (
	"fmt"
	"os"
)

func PrintOutErr() {
	for i := 0; i < 10; i++ {
		fmt.Fprintf(os.Stderr, "%v\n", i)
		fmt.Fprintf(os.Stdout, "%v\n", i)
	}
}
