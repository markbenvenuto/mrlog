# Mongo Rust Log Formatter

Converts MongoDB 4.4 log format to MongoDB 4.2 and prior style text logs

## Features
* Converts JSON to text
* Optional output coloring
* Subprocess execution
* Demangles C++ names automatically
* Optional decoding of stacktraces using DWARF to give line numbers (Linux only)

## Run

To read from standard in:

```cat <file> | mrlog```

To convert a file:

```mrlog <optional file>```

File is printed to standard out

**Advanced Features:**

To run a command and colorize its output:

```mrlog -c -e python -- buildscripts/resmoke.py ...```

Separate the command executable from its arguments with `--`.

To decode stacktraces using DWARF fromm mongod (Linux only).

```mrlog --decode=mongod <optional file>```


## Options

```
Convertes MongoDB 4.4 JSON log format to text format. Writes converted file to stdout

USAGE:
    mrlog [FLAGS] [path-or-args]...

FLAGS:
    -c, --color
    -e, --execute    Execute command and process output
    -h, --help       Prints help information
        --id         Log id in text log
    -V, --version    Prints version information

OPTIONS:
    -d, --decode <decode>    Decode backtraces with DWARF information from binary, split symbols not supported
    -o, --output <output>    Output file, stdout if not present

ARGS:
    <path-or-args>...    Optional path to the file to read, defaults to stdin In execute mode, a command to run and
                         a list of args
```

## Build
Get Rust from https://rustup.rs/.

```cargo build --release```

**Note**: Release builds are needed for good performance for decoding DWARF.

## License

Apache 2.0


TODO
- make MongoDB json format specify the name of the main binary
- color fatal and warning log messages
- https://github.com/BurntSushi/memchr ?

