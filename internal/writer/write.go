package writer

import (
	"fmt"
	"os"
	"path"

	"github.com/alegrey91/harpoon/internal/archiver"
	"github.com/alegrey91/harpoon/internal/seccomputils"
)

type WriteOptions struct {
	Save      bool
	Directory string
}

func Write(syscalls []uint32, functionSymbol string, opts WriteOptions) error {
	var errOut error
	if opts.Save {
		fileName := archiver.Convert(functionSymbol)
		err := os.MkdirAll(opts.Directory, os.ModePerm)
		if err != nil {
			return fmt.Errorf("error creating directory: %v", err)
		}
		file, err := os.Create(path.Join(opts.Directory, fileName))
		if err != nil {
			return fmt.Errorf("error creating file %s: %v", file.Name(), err)
		}
		defer file.Close()

		if err := file.Chmod(0744); err != nil {
			return fmt.Errorf("error setting permissions to %s: %v", file.Name(), err)
		}
		// write to file
		errOut = seccomputils.Print(file, syscalls)
	} else {
		// write to stdout
		errOut = seccomputils.Print(os.Stdout, syscalls)
	}
	if errOut != nil {
		return fmt.Errorf("error printing out system calls: %v", errOut)
	}

	return nil
}
