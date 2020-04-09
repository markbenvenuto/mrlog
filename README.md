# Mongo Rust Log Formatter

Converts MongoDB 4.4 log format to MongoDB 4.2 and prior style text logs

## Run

To read from standard in:

```cat <file> | mrlog```

To convert a file:

```mrlog <optional file>```

File is printed to standard out

To run a command and colorize its output:

```mrlog -c -e python -- buildscripts/resmoke.py ...```

Separate the command executable from its arguments with `--`.

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
```cargo build```

## License

Apache 2.0
