# Harpoon

<p align="center">
    <img src="harpoon.png" alt="gopher" width="200"/>
</p>

**Harpoon** aims to capture the syscalls (as if they were fishes) from the execution flow (the river) of a single user-defined function.

[![Awesome eBPF](https://awesome.re/badge.svg)](https://github.com/zoidyzoidzoid/awesome-ebpf?tab=readme-ov-file#security)

## Introduction

This tool is designed to provide fine-grained visibility into the syscalls made by specific functions within a program. Unlike traditional system call tracing tools like `strace`, which capture all syscalls made during the entire program's execution, this project leverages the power of **eBPF** to pinpoint and monitor system calls exclusively within targeted functions.

## Getting Started

First of all, let's identify the symbol of the function you want to trace from the binary. Suppose you want to trace the function `doSomething()` present in the example program `./binary`. In order to get the symbol from the binary itself, you need to use the following command:

```sh
objdump --syms ./binary | grep doSomething
0000000000480720 g     F .text  0000000000000067 main.doSomething
```

So, `main.doSomething` is the symbol of the function we want to trace using `harpoon`.

Then, let's run `harpoon` to extract the syscalls from the function `main.doSomething`:

```shell
harpoon capture -f main.doSomething -- ./binary
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

**Documentation:**

* [Commands](docs/commands.md)
* [Tutorials](docs/tutorials.md)

## Installation

To install `harpoon` you currently have 2 options:

### Download

You can easily download the latest release using the installation script:

```sh
curl -s https://raw.githubusercontent.com/alegrey91/harpoon/main/install | sudo bash
```

Alternatively, if you want to customize your installation, use the following flags:

```sh
curl -s https://raw.githubusercontent.com/alegrey91/harpoon/main/install | sudo bash -s -- --install-version v0.9 --install-dir ~/.local/bin/
```

(If your current version is `<= v0.8.2`, remove it from `/usr/local/bin/` before installing the new one).

### Build

Or you can build `harpoon` manually by using the following steps:

Install dependencies (for Ubuntu):

* `clang`
* `libbpf-dev`
* `libseccomp-dev`
* `linux-tools-generic` (for `bpftool`)

Install dependencies (for Fedora):

* `clang`
* `libbpf-devel`
* `libseccomp-devel`
* `elfutils-libelf-devel`
* `bpftool`

Build the application:

```sh
make build
```

After the build is completed, you can find the executable under the `bin/` directory.

## Debugging

In case you want to run the application locally, I've provided the [`.vscode/launch.json`](.vscode/launch.json) file to easily debug the application with `root` privileges in `vscode`.

## Talks

I had the pleasure of speaking about `harpoon` at the following conferences:

* [**GOLAB**](https://www.youtube.com/watch?v=A5A_Ll9o1Rc) (Nov 24) (EN)
* [**Golang Meetup Roma**](https://www.youtube.com/watch?v=iUg3fkoNxcY) (Sep 24) (IT)
* [**Conf42**](https://www.youtube.com/watch?v=Z8IHOTlG3pM) (Apr 24) (EN)
* [**FOSDEM**](https://fosdem.org/2024/schedule/event/fosdem-2024-1884-how-we-almost-secured-our-projects-by-writing-more-tests/) (Feb 24) (EN)

## Adopters

This is a list of projects that are using `harpoon` for generating **Seccomp** profiles on their pipeline:

* [**alegrey91/fwdctl**](https://github.com/alegrey91/fwdctl)
* [**projectcapsule/capsule**](https://github.com/projectcapsule/capsule)

## References

I would like to point out that without the references mentioned below this project would never have come to life.
As a result, the code draws significant inspiration from the references listed here:

* https://www.grant.pizza/blog/tracing-go-functions-with-ebpf-part-1/
* https://itnext.io/seccomp-in-kubernetes-part-2-crafting-custom-seccomp-profiles-for-your-applications-c28c658f676e
* https://github.com/containers/oci-seccomp-bpf-hook
* https://sysdig.com/blog/ebpf-offensive-capabilities/
* *Liz Rice. Learning eBPF, 173-176. O'Reilly, 2023*

