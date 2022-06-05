# fudo
Command line utility to encrypt binary distributions, launch encrypted binaries without ever storing plaintext on disk, decrypt files, and scrub files from disk.

## Building
`cargo build`

## Running
```
USAGE:
    fudo <SUBCOMMAND>

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    decrypt
    encrypt
    help       Print this message or the help of the given subcommand(s)
    launch
    scrub
```

# TODO
- Add -j flag for speeding up crypto
- Add -v flag for debug information
- Sanitize environment variables after executing fexecve(2)
- Allow passing in custom environment variables
- Windows support
- Migrate system calls to palaver
