# Playground
Includes a simple `main.c` snippet to test that `argv` and `envp` are forwarded properly.
To run:

```
gcc main.c -o main
cd ..
cargo run encrypt main -o main.enc
cargo run launch main.enc --forward-args "1 2 3 4 5"
```
