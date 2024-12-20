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
	FileName  string
	Directory string
}

func Write(syscalls []uint32, functionSymbol string, opts WriteOptions) error {
	var errOut error
	if opts.Save {
		fileName := archiver.Convert(functionSymbol)
		if opts.FileName != "" {
			fileName = opts.FileName
		}
		if fileName == "" {
			return fmt.Errorf("file name is empty")
		}
		err := os.MkdirAll(opts.Directory, os.ModePerm)
		if err != nil {
			return fmt.Errorf("error creating directory: %v", err)
		}
		path := path.Join(opts.Directory, fileName)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("error creating file %s: %v", path, err)
		}
		defer file.Close()

		if err := file.Chmod(0744); err != nil {
			return fmt.Errorf("error setting permissions to %s: %v", path, err)
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
