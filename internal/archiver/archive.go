package archiver

import (
	"strings"
)

func Convert(name string) string {
	name = strings.Replace(name, "/", "_", -1)
	name = strings.Replace(name, ".", "_", -1)
	return name
}
