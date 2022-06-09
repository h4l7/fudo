# fudo
Command line utility to encrypt binary distributions, launch encrypted binaries without ever storing plaintext on disk, decrypt files, and scrub files from disk.

## Building
`cargo build`

## Running
`./target/debug/fudo --help`

See `./playground` for examples.

## TODO
- Add -v flag for debug information
- Windows support
- Improve --forward-env structure