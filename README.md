# agilecrypto (Rust)

The citius C API (`agc_*`, the headers in `../citius-c-api/include/agc`)
implemented in Rust and called from C. Structured like citius-core:
domain-driven, with the same domains and orchestrators.

- The headers are owned by citius-c-api and read in place, not copied.
  `HEADERS_PIN` names the citius-c-api revision this crate implements
  (`tests/headers_pin.rs` fails if the checkout differs); set
  `AGC_INCLUDE_DIR` to read them from somewhere else.
- `build.rs` runs bindgen on `agilecrypto.h` (all headers) to generate the
  Rust types and declarations. It also generates compile-time checks that
  every function in `src/ffi/exports` matches its C declaration.
- Every header function is exported (`abi_skip.txt`, the list of missing
  ones, is empty). The operations the Go server does not implement return
  `AGC_ERR_NOT_IMPLEMENTED`; they are in `src/ffi/exports/stubs.rs`.
- `DEVIATIONS.md` records every deliberate difference from the Go
  implementation and from the C stub in citius-c-api.

## Layout

Dependencies point down only; `tests/architecture.rs` enforces it.

```
src/ffi/        the C boundary, the only layer that knows the C types:
                exports/ (one file per header), pointer and struct_size
                handling, error -> agc_rc mapping, agc_last_error
src/app/        orchestrators: one method per use case, over domain traits
src/domain/     core (shared vocabulary), key, policy, template, provider,
                crypto; a domain uses only core and itself
src/adapters/   implementations of domain traits (storage, providers)
```

## Build and test

Requires a Rust toolchain, libclang (for bindgen) and a C compiler.

```sh
cargo build                 # target/debug/libagilecrypto.{a,dylib|so}
cargo test --workspace      # Rust unit tests, architecture, header pin
cargo xtask test-c          # builds the library, checks its exported
                            # symbols, runs tests/c/*.c plain and with
                            # ASan+UBSan
cargo xtask miri            # the unit tests under Miri (undefined behaviour
                            # in unsafe code, data races between Rust threads)
cargo xtask tsan            # tests/c/*.c against a library built with
                            # ThreadSanitizer, Rust std included
cargo xtask interop         # signatures, ciphertexts and metadata
                            # cross-checked with Go's software provider
cargo xtask all             # test-c, miri, tsan and interop
```

`cargo xtask test-c` always rebuilds the library first: `cargo test` does not
rebuild the cdylib, so linking C against it directly can test stale code.

`miri` and `tsan` need a nightly toolchain next to the default one:
`rustup toolchain install nightly --component miri --component rust-src`.
The xtask finds it through rustup, so `cargo +nightly` is not needed.

`interop` needs Go and a citius-server checkout (`CITIUS_SERVER_DIR`,
default `../citius-server`). Rust signs and encrypts with every template and
Go's software provider verifies and decrypts; then the reverse. Each side
also decodes the other's metadata. `interop/go/interop_test.go` is placed
into the provider's package with `go test -overlay`; the checkout is not
modified.

Why the sanitizers are set up this way:
- ASan+UBSan instrument only the C test code; the Rust library is linked
  uninstrumented. They catch misuse of caller memory, not bugs inside Rust.
  Miri covers the Rust side.
- For TSan both sides are instrumented. A process may hold only one TSan
  runtime: on macOS the C tests link Rust's (`librustc-nightly_rt.tsan`),
  not clang's.

## Before pushing

`.githooks/pre-push` runs clippy, `cargo test` and `cargo xtask test-c`
(a minute or two). Miri, TSan and interop take several minutes; run them with
`AGC_FULL_CHECKS=1 git push` or `cargo xtask all` at the end of each phase
and before releases. Enable the hook once per clone:

```sh
git config core.hooksPath .githooks
# A long hook can outlast the server's idle timeout on the push connection:
git config core.sshCommand "ssh -o ServerAliveInterval=15"
```

## CI

`.github/workflows/ci.yml` checks out this repository and citius-c-api (at
`HEADERS_PIN`) side by side and runs clippy, `cargo test`, `cargo xtask
test-c`, Miri and TSan (on a pinned nightly, `XTASK_NIGHTLY`), and `cargo
audit`. citius-c-api is public, so CI needs no secrets.

## Install and use from C

```sh
cargo xtask install --prefix /opt/agilecrypto
```

installs the release library, the headers and the build-system files:

```
lib/libagilecrypto.1.dylib        (libagilecrypto.so.1 on Linux)
lib/libagilecrypto.dylib          -> libagilecrypto.1.dylib, for linking
lib/libagilecrypto.a
include/agc/*.h
lib/pkgconfig/agilecrypto.pc
lib/cmake/agilecrypto/            find_package(agilecrypto 1.0)
```

The shared library's name carries the API's major version (1): a program
built against it records `libagilecrypto.so.1` and never loads a library of
another major version. `build.rs` refuses to build if Cargo.toml's major
version and the headers' `AGC_API_VERSION_MAJOR` differ.

```sh
cc app.c $(pkg-config --cflags --libs agilecrypto)          # dynamic
cc app.c $(pkg-config --cflags agilecrypto) /opt/agilecrypto/lib/libagilecrypto.a \
   $(pkg-config --static --libs-only-l agilecrypto | sed 's/-lagilecrypto//')   # static
```

```cmake
find_package(agilecrypto 1.0 REQUIRED)
target_link_libraries(app PRIVATE agilecrypto::agilecrypto)
```

`examples/c/` holds three small programs, built and run by `cargo xtask
test-c` with the tests: encrypt/decrypt, sign/verify, and a persistent key
store.

## Keeping keys: the file key store

By default a context keeps keys in memory. To keep them across runs:

```c
cfg.key_store_uri = "file:/var/lib/myapp/keys";
cfg.key_store_wrapping_key_path = "/etc/myapp/wrapping.key";
```

- Each key is one file in the directory, sealed with AES-256-GCM under the
  wrapping key and bound to its key id, so a record that is edited or moved
  onto another key does not open. Writes replace a file atomically.
- The wrapping key file holds 32 bytes and must be readable by its owner
  only; it is read once, when the context opens. Losing it loses the keys.
- One context uses a store at a time: a second, in any process, fails with
  `AGC_ERR_CRYPTO_CONCURRENT_ACCESS`. That includes a forked child, while the
  parent keeps the store open.
- Policies are not stored. An application creates them each time it opens
  a context; keys name their policy, and fail closed until it exists.

## License

Apache License 2.0; see [LICENSE](LICENSE).
