# api-test-extended

A C API (the headers in `include/`) implemented in Rust and called from C.

- `build.rs` runs bindgen on `include/agc_key.h` to generate the Rust types
  and declarations. It also generates compile-time checks that every function
  in `src/exports.rs` matches its C declaration.
- Functions that are not implemented yet are listed in `abi_skip.txt`. When
  you implement one, remove its line from that file.
- `src/exports.rs` contains the `extern "C"` entry points. They check the raw
  pointers and then call the Rust logic in `src/exports/service.rs`.
- `examples/c/main.c` is a small C program that calls `agc_create_key`.

## Build the Rust library

Requires a Rust toolchain and libclang, which bindgen uses.

```sh
cargo build
```

This produces `target/debug/libapi_test_extended.a` and a shared library
(`.dylib` on macOS, `.so` on Linux).

## Build and run the C example

From the crate root, after `cargo build`:

```sh
cc -Wall -Wextra -I include examples/c/main.c -L target/debug -lapi_test_extended -o target/c_example
./target/c_example
```
