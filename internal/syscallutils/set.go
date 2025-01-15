package syscallutils

// To obtain the following lists of syscalls I used this piece of code.
// This was needed because it makes use of the "net" package which calls out to libc.
// This was done to force dynamic linking.
/*
package main

import (
    "fmt"
	"net"
)

func main() {
	fmt.Println(net.LookupHost("google.com"))
}
*/

// Syscalls executed by dynamically linked Go binary to start/stop process
// This was obtained compiling a minimal piece of Go code with the following command:
// go build -o bin-dynamic .
// strace ./bin-dynamic | cut -d '(' -f 1 | sort | uniq
// N.B. the binary will contain other syscalls (eg. write) which are part of the `main` function,
// so I removed it for correctness.
var MinDynamicGoSyscallSet = []string{
	"access",
	"arch_prctl",
	"brk",
	"clone3",
	"close",
	"execve",
	"exit_group",
	"fcntl",
	"fstat",
	"futex",
	"getrandom",
	"getrlimit",
	"gettid",
	"madvise",
	"mmap",
	"mprotect",
	"munmap",
	"openat",
	"pread64",
	"prlimit64",
	"read",
	"rseq",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigreturn",
	"sched_getaffinity",
	"setrlimit",
	"set_robust_list",
	"set_tid_address",
	"sigaltstack",
}

// Syscalls executed by statically linked Go binary to start/stop process.
// This was obtained compiling a minimal piece of Go code with the following command:
// CGO_ENABLED=0 go build -o bin-static .
// strace ./bin-static | cut -d '(' -f 1 | sort | uniq
// N.B. the binary will contain other syscalls (eg. write) which are part of the `main` function,
// so I removed it for correctness.
var MinStaticGoSyscallSet = []string{
	"arch_prctl",
	"clone",
	"close",
	"execve",
	"exit_group",
	"fcntl",
	"futex",
	"getrlimit",
	"gettid",
	"madvise",
	"mmap",
	"openat",
	"read",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigreturn",
	"sched_getaffinity",
	"setrlimit",
	"sigaltstack",
}

// Syscalls executed by runc due to an early seccomp startup issue:
// https://github.com/moby/moby/issues/22252
// The seccomp profile starts early, so this needs the syscalls of the container engine too.
// This is documented here: 
// https://github.com/docker/labs/blob/master/security/seccomp/README.md#step-6-a-few-gotchas
var MinDockerSyscallSet = []string{
	"capget",
	"capset",
	"chdir",
	"epoll_pwait",
	"eventfd",
	"eventfd2",
	"fchown",
	"futex",
	"fstatfs",
	"getcwd",
	"getdents64",
	"geteuid",
	"getpgrp",
	"getpid",
	"getppid",
	"ioctl",
	"lstat",
	"lseek",
	"newfstatat",
	"openat",
	"prctl",
	"setgid",
	"setgroups",
	"setsid",
	"setuid",
	"stat",
}
