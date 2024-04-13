# Harpoon

<p align="center">
    <img src="harpoon.png" alt="gopher" width="200"/>
</p>

**Harpoon** aims to capture the syscalls (as if they were fishes) from the execution flow (the river) of a single user-defined function.

**N.B.** This is currently a PoC made for fun in my free time. Definitely, not a production grade project.

## Introduction

This tool is designed to provide fine-grained visibility into the syscalls made by specific functions within a program. Unlike traditional system call tracing tools like `strace`, which capture all syscalls made during the entire program's execution, this project leverages the power of **eBPF** to pinpoint and monitor system calls exclusively within targeted functions.

## Getting Started

First of all, identify the symbol of the function you want to trace from the binary. Let's suppose you want to trace the function `doSomething()` present in the example program `./binary`. In order to get the symbol from the binary itself, you need to use the following command:

```sh
objdump --syms ./binary | grep doSomething
0000000000480720 g     F .text  0000000000000067 main.doSomething
```

So, `main.doSomething` is the symbol of the function we want to trace using `harpoon`.

Then, let's run `harpoon` to extract the syscalls from the function `main.doSomething`:

```shell
harpoon -fn main.doSomething ./binary
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

These are the syscalls that have been executed by the traced function!

## Installation

### Build

Once you have all the needed tools to run `harpoon`, you can build it locally with:

```sh
make build
```

After the build is completed, you can find the executable under the `bin/` directory.

### Download

Alternatively, you can easily download the latest release using the one liner:

```sh
curl -s https://raw.githubusercontent.com/alegrey91/harpoon/main/install | sudo sh
```

## Debugging

In case you want to run the application locally, I've provided the [`.vscode/launch.json`](.vscode/launch.json) file to easily debug the application with `root` privileges in `vscode`. Just replace the parameters marked with `<>`.

## Talks

I had the pleasure of presenting `harpoon` at the following conferences:
* [**FOSDEM**](https://fosdem.org/2024/schedule/event/fosdem-2024-1884-how-we-almost-secured-our-projects-by-writing-more-tests/)

## References

I would like to point out that without the references mentioned below this project would never have come to life.
As a result, the code draws significant inspiration from the references listed here:

* https://www.grant.pizza/blog/tracing-go-functions-with-ebpf-part-1/
* https://itnext.io/seccomp-in-kubernetes-part-2-crafting-custom-seccomp-profiles-for-your-applications-c28c658f676e
* https://github.com/containers/oci-seccomp-bpf-hook
* https://sysdig.com/blog/ebpf-offensive-capabilities/
* *Liz Rice. Learning eBPF, 173-176. O'Reilly, 2023*

