# Harpoon

<p align="center">
    <img src="harpoon.png" alt="gopher" width="200"/>
</p>

**Harpoon** aims to capture the syscalls (as if they were fishes) from the execution of a single user-defined function.

**N.B.** This is currently a PoC made for fun in my free time. Not a production grade project.

## Introduction

This tool is designed to provide fine-grained visibility into the syscalls made by specific functions within a program. Unlike traditional system call tracing tools like `strace`, which capture all syscalls made during the entire program's execution, this project leverages the power of eBPF to pinpoint and monitor system calls exclusively within targeted functions.

## Getting Started

First of all, identify the symbol of the function you want to trace from the binary. Let's suppose you want to trace the function `doSomething()` present in the program `./binary`. In order to get the symbol from the binary itself, you need to use the following command:

```sh
objdump --syms ./binary | grep doSomething
0000000000480720 g     F .text  0000000000000067 main.doSomething
```

So, `main.doSomething` is the symbol of the function we want to trace using `harpoon`.

Then, let's run `harpoon` to extract the syscalls from the function `main.doSomething`:

```sh
harpoon -f main.doSomething ./binary
[+] start tracing
[+] stop tracing
read
sigaltstack
gettid
close
mmap
fcntl
write
futex
openat
clone
getrlimit
```

That's the list of syscalls that have been executed during the tracked function!

## References

I would like to point out that without the references mentioned below this project would never have come to life.
For that reason, the code takes a lot of inspiration from the references listed below:

* https://www.grant.pizza/blog/tracing-go-functions-with-ebpf-part-1/
* https://itnext.io/seccomp-in-kubernetes-part-2-crafting-custom-seccomp-profiles-for-your-applications-c28c658f676e
* https://github.com/containers/oci-seccomp-bpf-hook
* https://sysdig.com/blog/ebpf-offensive-capabilities/
* *Liz Rice. Learning eBPF. O'Reilly, 2023*

