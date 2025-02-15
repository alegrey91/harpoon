package syscallutils

import "regexp"

var re = regexp.MustCompile(`[0-9]+$`)

var syscallGroups = map[string][]string{
	"accept":          {"accept", "accept4"},
	"clone":           {"clone", "clone2", "clone3"},
	"dup":             {"dup", "dup2", "dup3"},
	"epoll_create":    {"epoll_create", "epoll_create1"},
	"epoll_pwait":     {"epoll_pwait", "epoll_pwait2"},
	"eventfd":         {"eventfd", "eventfd2"},
	"faccessat":       {"faccessat", "faccessat2"},
	"inotify_init":    {"inotify_init", "inotify_init1"},
	"mlock":           {"mlock", "mlock2"},
	"mmap":            {"mmap", "mmap2"},
	"openat":          {"openat", "openat2"},
	"pipe":            {"pipe", "pipe2"},
	"preadv":          {"preadv", "preadv2"},
	"pwritev":         {"pwritev", "pwritev2"},
	"renameat":        {"renameat", "renameat2"},
	"signalfd":        {"signalfd", "signalfd4"},
	"sync_file_range": {"sync_file_range", "sync_file_range2"},
	"umount":          {"umount", "umount2"},
}

func GetVariants(syscall string) []string {
	if syscall == "" {
		return nil
	}
	seed := re.ReplaceAllString(syscall, "")
	if variants, ok := syscallGroups[seed]; ok {
		return variants
	}
	return nil
}
