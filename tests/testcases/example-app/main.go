/*
Copyright © 2023 Alessio Greggi alessiog@armosec.io

*/
package main

import (
	"fmt"
	"syscall"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"github.com/alegrey91/seccomp-test-coverage/cmd"
)

func whiteList(syscalls []string) {

	filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		fmt.Printf("Error creating filter: %s\n", err)
	}
	for _, element := range syscalls {
		fmt.Printf("[+] Whitelisting: %s\n",element)
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			panic(err)
		}
		filter.AddRule(syscallID, libseccomp.ActAllow)
	}
	filter.Load()
}

func main() {

	//var syscalls = []string{"access", "brk", "clone", "close", "execve", "fcntl", "futex", "getpid", "getrandom", "getrlimit", "gettid", "lseek", "madvise", "mmap", "mprotect", "munmap", "newfstatat", "openat", "read", "renameat", "rseq", "setrlimit", "sigaltstack", "write", "exit_group"}
	//whiteList(syscalls)
	cmd.Execute()
}
