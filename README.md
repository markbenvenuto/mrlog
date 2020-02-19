# Mongo Rust Log Formatter

Converts MongoDB 4.4 log format to MongoDB 4.2 and prior style text logs

## Run

To read from standard in:

```cat <file> | mrlog```

To convert a file:

```mrlog <optional file>```

File is printed to standard out

## Build
```cargo build```

## License

Apache 2.0
