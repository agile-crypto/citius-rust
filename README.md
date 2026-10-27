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
- Functions that are not implemented yet are listed in `abi_skip.txt`,
  grouped by header. When you implement one, remove its line from that file.
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
cargo xtask all             # test-c, miri and tsan
```

`cargo xtask test-c` always rebuilds the library first: `cargo test` does not
rebuild the cdylib, so linking C against it directly can test stale code.

`miri` and `tsan` need a nightly toolchain next to the default one:
`rustup toolchain install nightly --component miri --component rust-src`.
The xtask finds it through rustup, so `cargo +nightly` is not needed.

Why the sanitizers are set up this way:
- ASan+UBSan instrument only the C test code; the Rust library is linked
  uninstrumented. They catch misuse of caller memory, not bugs inside Rust.
  Miri covers the Rust side.
- For TSan both sides are instrumented. A process may hold only one TSan
  runtime: on macOS the C tests link Rust's (`librustc-nightly_rt.tsan`),
  not clang's.

## Before pushing

`.githooks/pre-push` runs clippy, `cargo test` and `cargo xtask all`, which is
everything CI runs. Enable it once per clone:

```sh
git config core.hooksPath .githooks
```

## CI

`.github/workflows/ci.yml` checks out this repository and citius-c-api (at
`HEADERS_PIN`) side by side and runs clippy, `cargo test`, `cargo xtask
test-c`, Miri and TSan (on a pinned nightly, `XTASK_NIGHTLY`), and `cargo
audit`. It needs a repository secret `CITIUS_C_API_SSH_KEY`: the private half
of a read-only deploy key on citius-c-api.

GitHub Actions is currently disabled for the repository, so the pre-push hook
is the gate until it is enabled.

## Build and run the C example

From the crate root, after `cargo build`:

```sh
cc -Wall -Wextra -I ../citius-c-api/include/agc examples/c/main.c -L target/debug -lagilecrypto -o target/c_example
./target/c_example
```
