# Commands

Harpoon has several commands that you can use.

The common way of using `harpoon` is to execute the available commands as follow:

* [`harpoon analize`](#analyze-) to analyze the project to infer symbols to be traced. This will create a `.harpoon.yml` file.

* [`harpoon hunt`](#hunt-) by passing the `.harpoon.yml` file to trace the functions and get their system calls. This will generate the `./harpoon/` directory with the metadata that contains the system calls traced.

* [`harpoon build`](#build-️) to read the metadata files and provide the **seccomp** profile.

## Analyze

The `analyze` command is used to analyze the project's folder and get the list of function symbols you want to trace.

Additionally it automatically build the test binary and place them into the `harpoon/` directory.

The result of this command is the `.harpoon.yml` file with the list of test binaries followed by their function symbols that are currently tested.

Run it on your project folder:

```sh
sudo harpoon analyze --exclude .git/ .
```

## Build

The `build` command collect the metadata files (created by the `hunt` command under the `harpoon/` directory) and use them to create a **seccomp** profile based on their content.

```sh
sudo harpoon build -D ./harpoon/
```

## Capture

The `capture` command is the "core" of `harpoon`. This trace the function symbols passed as argument for the give binary.

```sh
sudo harpoon capture -f github.com/user/repo/pkg/pkgname.functionName .harpoon/packagebin.test
```

The result, is a list of system call executed by the function during the run of the binary.

## Hunt

The `hunt` command is similar to `capture`, but used to capture a list of functions from different test binary.

The command needs a file as input paramenter that is the result of the `analyze` command.

This will loop over the entries of the file, capturing the system calls of each entry.

```sh
harpoon hunt --file .harpoon.yml -S
```

This will create the directory `harpoon/` with the list of system calls traced from the execution of the different test binaries present in the `.harpoon.yml` file.