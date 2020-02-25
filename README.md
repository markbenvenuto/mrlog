# Mongo Rust Log Formatter

Converts MongoDB 4.4 log format to MongoDB 4.2 and prior style text logs

## Run

To read from standard in:

```cat <file> | mrlog```

To convert a file:

```mrlog <optional file>```

File is printed to standard out

## Options

```
Convertes MongoDB 4.4 JSON log format to text format. Writes converted file to stdout

USAGE:
    mrlog [FLAGS] [path]

FLAGS:
    -c, --color
    -h, --help       Prints help information
        --id         Log id to text log
    -V, --version    Prints version information

ARGS:
    <path>    Optional path to the file to read, defaults to stdin
```

## Build
```cargo build```

## License

Apache 2.0
