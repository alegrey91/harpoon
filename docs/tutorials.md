# Tutorials

Here are listed some tutorials to use `harpood` within your project.

## Tracing single function

`harpoon` was made with the intent fo tracing user-defined functions from binaries.

Suppose you have the following piece of code in your code base and you want to know which system calls are executed during its run:

```golang
func doSomething() {
    fmt.Println("hello")
}
```

In order to do so, you need to build the code so you can inspect the binary content. What we actually need is the symbol's name of the function `doSomething()` withing the binary. If the function is really short the compiler could omit the symbol within the binary, so in order to force it to insert the symbol, use the `-gcflags="-N -l"` option when compiling.

```sh
objdump --syms ./binary_name | grep doSomething
0000000000480720 g     F .text  0000000000000067 main.doSomething
```

Ok, so we know that the symbol name of the function `doSomething()` is `main.doSomething` within the compiled binary.

Now, what we need is to run the binary so that the function will be executed and we will be able to trace it with `harpoon`:

```sh
harpoon capture -f main.doSomething -- ./binary_name
write
```

So `write` is the syscall executed by the function `doSomething()`.

## Tracing multiple functions

`harpoon` supports tracing multiple functions at the same time. This helps when we want to trace the syscalls from an entire package.

Suppose we want to trace the following functions: `doSomething()` and `DoLess()`.

As above, first we have to find the symbol's names within the binary with `objdump`.
`objedump` returns, in this case, the following items:
* `main.doSomething`
* `test/internal.DoLess`

Once found the symbols we are ready to run `harpoon` to trace the functions all togheter:

```sh
harpoon capture -f "main.doSomething" -f "test/internal.DoLess" -- ./binary_name
write
write
```

As you can see all the functions are using the `write` syscall inside them.

## Tracing entire process

What makes `harpoon` really versatile is the fact that you can trace single functions within the binary.

Since `main` is in turn a user-defined function, we can trace the execution of this with `harpoon`. This is extremely useful if we want to use `harpoon` to trace integration tests.

But, being tracing `main` it also means that we are tracing the entire process from the begin to the end :)

```sh
harpoon capture -f main.main -- ./binary_name
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

So the listed syscalls are the ones executed by the process during its run.

## Tracing a program that doesn't stop

`harpoon` allows you trace a program that doesn't stop (eg. a web server).

To do so, you have the `--dump-interval/-i` flag available. This flag gives you the ability to dump the collected syscalls every interval of time.

```sh
harpoon capture -f main.main --dump-interval 2 -- ./binary_name
```

## Tracing a program that requires environment variables to run

`harpoon` provides support to pass environment variables to the executed command.

This is really useful to trace the command changing its behaviour through env vars.

Here's how you can pass multiple env vars to the executed command:

```sh
harpoon capture -f main.main -E "VAR1=value1" -E "VAR2=value2" -- ./binary_name
```

## Tracing from unit-tests

`harpoon` has additional commands other than `capture`. The commands are `analyze` and `hunt`.

Let's see how to take advantage of them for tracing syscalls from unit-tests.

```sh
harpoon analyze --exclude .git/
```

This command parses all the `go` files in the code base and generates a report called `harpoon-report.yml`.

Once created this file, we can pass it to the next command:

```sh
harpoon hunt --file harpoon-report.yml -S
```

This creates the `harpoon/` directory containing all the metadata files, one for each function traced.
