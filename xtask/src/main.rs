//! Developer tasks that need more than `cargo test`.
//!
//!   cargo xtask test-c         build the library, check its exported symbols,
//!                              compile and run tests/c/*.c plain and with
//!                              ASan+UBSan
//!   cargo xtask check-symbols  only the symbol check
//!   cargo xtask memcheck       tests/c/*.c with a checking allocator around
//!                              the whole process, the library included:
//!                              Guard Malloc (macOS), valgrind (Linux)
//!   cargo xtask miri           run the library's unit tests under Miri
//!   cargo xtask tsan           build the library with ThreadSanitizer and run
//!                              tests/c/*.c against it
//!   cargo xtask interop        cross-check signatures, ciphertexts and
//!                              metadata with the Go software provider
//!                              (needs Go and a citius-server checkout)
//!   cargo xtask install --prefix DIR
//!                              build the release library and install it,
//!                              its headers, pkg-config file and CMake
//!                              package under DIR
//!   cargo xtask all            everything above but install
//!   cargo xtask bench [--quick] [--csv FILE] [--only SECTION]
//!                              build the release library and run the C
//!                              benchmark harness benches/c/bench.c (the
//!                              agc_* path, docs/performance.md)
//!
//! The library is always built first: `cargo test` does not rebuild the
//! cdylib, and a C test linked against a stale one tests old code.
//!
//! `miri` and `tsan` need a nightly toolchain with the miri and rust-src
//! components; it is found through rustup, so the default toolchain stays as
//! it is. `XTASK_NIGHTLY` names it (default `nightly`), e.g. a dated nightly
//! pinned in CI.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const LIB: &str = "agilecrypto";
const PACKAGE: &str = "agilecrypto";

fn main() -> ExitCode {
    let task = env::args().nth(1).unwrap_or_default();
    let result = match task.as_str() {
        "test-c" => test_c(),
        "check-symbols" => build().and_then(|b| check_symbols(&b)),
        "memcheck" => memcheck(),
        "miri" => miri(),
        "tsan" => tsan(),
        "interop" => interop(),
        "install" => install(&env::args().skip(2).collect::<Vec<_>>()),
        "bench" => bench(&env::args().skip(2).collect::<Vec<_>>()),
        "all" => test_c().and_then(|()| miri()).and_then(|()| tsan()).and_then(|()| interop()),
        _ => Err("usage: cargo xtask <test-c|check-symbols|memcheck|miri|tsan|interop|install --prefix DIR|all\
                  |bench [--quick] [--csv FILE] [--only SECTION]>"
            .to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_owned()
}

fn include_dir() -> PathBuf {
    env::var_os("AGC_INCLUDE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("../citius-c-api/include/agc"))
}

fn run(cmd: &mut Command, what: &str) -> Result<(), String> {
    let status = cmd.status().map_err(|e| format!("cannot run {what}: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("{what} failed ({status})")) }
}

fn output(cmd: &mut Command, what: &str) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("cannot run {what}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{what} failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

struct Built {
    /// Directory holding the cdylib.
    lib_dir: PathBuf,
    /// The library's build-script output (bindings, header_functions.txt).
    out_dir: PathBuf,
}

fn build() -> Result<Built, String> {
    let stdout = output(
        Command::new(env!("CARGO"))
            .current_dir(root())
            .args(["build", "--package", PACKAGE, "--message-format=json"]),
        "cargo build",
    )?;
    // One JSON object per line; the build script's line names its out_dir.
    let out_dir = stdout
        .lines()
        .filter(|l| l.contains(r#""reason":"build-script-executed""#) && l.contains(PACKAGE))
        .find_map(|l| json_string(l, "out_dir"))
        .ok_or("cargo build did not report the build script's out_dir")?;
    let lib_dir = root().join("target/debug");
    link_versioned(&lib_dir)?;
    Ok(Built { lib_dir, out_dir: PathBuf::from(out_dir) })
}

/// The library's major version, which its versioned file name and soname
/// carry (build.rs checks it equals the headers' AGC_API_VERSION_MAJOR).
fn major_version() -> Result<String, String> {
    Ok(cargo_package_version()?.split('.').next().unwrap_or_default().to_owned())
}

/// The versioned name of the shared library: libagilecrypto.so.<major> on
/// Linux, libagilecrypto.<major>.dylib on macOS.
fn versioned_cdylib_name() -> Result<String, String> {
    let major = major_version()?;
    Ok(if cfg!(target_os = "macos") { format!("lib{LIB}.{major}.dylib") } else { format!("lib{LIB}.so.{major}") })
}

/// Makes the versioned name resolve next to a freshly built cdylib: the
/// library records it as its install name / soname, so programs linked
/// against it look for that name at run time.
fn link_versioned(lib_dir: &Path) -> Result<(), String> {
    let versioned = lib_dir.join(versioned_cdylib_name()?);
    let _ = fs::remove_file(&versioned);
    std::os::unix::fs::symlink(cdylib(lib_dir).file_name().unwrap(), &versioned)
        .map_err(|e| format!("{}: {e}", versioned.display()))
}

/// The string value of `"key":"..."` in one line of cargo's JSON output.
/// Cargo writes paths without escapes other than `\\` and `\"`.
fn json_string(line: &str, key: &str) -> Option<String> {
    let start = line.find(&format!(r#""{key}":""#))? + key.len() + 4;
    let mut value = String::new();
    let mut chars = line[start..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(value),
            '\\' => value.push(chars.next()?),
            c => value.push(c),
        }
    }
    None
}

fn cdylib(lib_dir: &Path) -> PathBuf {
    let ext = if cfg!(target_os = "macos") { "dylib" } else { "so" };
    lib_dir.join(format!("lib{LIB}.{ext}"))
}

/// The nightly toolchain: its `bin` directory and host triple.
struct Nightly {
    bin: PathBuf,
    sysroot: PathBuf,
    host: String,
}

fn nightly() -> Result<Nightly, String> {
    const HINT: &str = "install it with: rustup toolchain install nightly --component miri --component rust-src";
    let toolchain = env::var("XTASK_NIGHTLY").unwrap_or_else(|_| "nightly".to_owned());
    let cargo = output(Command::new("rustup").args(["which", "--toolchain", &toolchain, "cargo"]), "rustup which")
        .map_err(|e| format!("no {toolchain} toolchain ({e}); {HINT}"))?;
    let bin = PathBuf::from(cargo.trim()).parent().unwrap().to_owned();
    let rustc = bin.join("rustc");
    let sysroot = PathBuf::from(output(Command::new(&rustc).args(["--print", "sysroot"]), "rustc")?.trim());
    let host = output(Command::new(&rustc).arg("-vV"), "rustc")?
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or("rustc -vV printed no host")?
        .to_owned();
    Ok(Nightly { bin, sysroot, host })
}

impl Nightly {
    /// A nightly `cargo` with the nightly `bin` first on PATH, so that cargo
    /// finds `cargo-miri` there rather than in a stable toolchain on PATH.
    fn cargo(&self) -> Command {
        let mut path = OsString::from(&self.bin);
        if let Some(old) = env::var_os("PATH") {
            path.push(":");
            path.push(old);
        }
        let mut cmd = Command::new(self.bin.join("cargo"));
        cmd.current_dir(root()).env("PATH", path).env_remove("RUSTUP_TOOLCHAIN");
        cmd
    }
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

/// The cdylib must export exactly the header functions that are implemented:
/// declared in the headers and not in abi_skip.txt. build.rs proves every
/// implemented function has the header's signature; this proves nothing
/// else leaks out and nothing implemented is missing from the binary.
fn check_symbols(b: &Built) -> Result<(), String> {
    let declared = read_names(&b.out_dir.join("header_functions.txt"))?;
    let skipped = read_names(&root().join("abi_skip.txt"))?;
    let expected: BTreeSet<_> = declared.difference(&skipped).cloned().collect();

    let nm = output(Command::new("nm").args(["-g", "--defined-only"]).arg(cdylib(&b.lib_dir)), "nm")?;
    let exported: BTreeSet<String> = nm
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        // Mach-O prefixes C symbols with an underscore.
        .map(|s| if cfg!(target_os = "macos") { s.strip_prefix('_').unwrap_or(s) } else { s })
        .filter(|s| s.starts_with("agc_"))
        .map(str::to_owned)
        .collect();

    let missing: Vec<_> = expected.difference(&exported).collect();
    let extra: Vec<_> = exported.difference(&expected).collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(format!("exported symbols differ from the headers:\n  missing: {missing:?}\n  extra:   {extra:?}"));
    }
    println!("symbols: {} agc_* functions exported, as expected", exported.len());
    Ok(())
}

fn read_names(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(text
        .lines()
        .map(|l| l.split('#').next().unwrap().trim())
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}

fn test_c() -> Result<(), String> {
    let b = build()?;
    check_symbols(&b)?;
    let asan = ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"];
    run_c_tests(&[
        Variant { name: "plain", lib_dir: b.lib_dir.clone(), compile: vec!["-O1"], ..Variant::default() },
        Variant {
            name: "asan-ubsan",
            lib_dir: b.lib_dir,
            compile: asan.to_vec(),
            link: asan.iter().map(|f| f.to_string()).collect(),
            ..Variant::default()
        },
    ])
}

/// The C tests with a checking allocator around the whole process, the
/// Rust library included (ASan in test-c instruments only the C side):
/// - macOS: Guard Malloc, every allocation against a guard page, once with
///   the guard after it (overflows) and once before (underflows);
/// - Linux: Valgrind memcheck.
fn memcheck() -> Result<(), String> {
    let b = build()?;
    let base = |name| Variant { name, lib_dir: b.lib_dir.clone(), compile: vec!["-O1", "-g"], ..Variant::default() };
    if cfg!(target_os = "macos") {
        const GMALLOC: &str = "/usr/lib/libgmalloc.dylib";
        if !Path::new(GMALLOC).exists() {
            return Err(format!("{GMALLOC} not found (Guard Malloc ships with macOS)"));
        }
        run_c_tests(&[
            Variant { run_env: vec![("DYLD_INSERT_LIBRARIES", GMALLOC)], ..base("gmalloc-after") },
            Variant {
                run_env: vec![("DYLD_INSERT_LIBRARIES", GMALLOC), ("MALLOC_PROTECT_BEFORE", "1")],
                ..base("gmalloc-before")
            },
        ])
    } else if cfg!(target_os = "linux") {
        output(Command::new("valgrind").arg("--version"), "valgrind --version")
            .map_err(|_| "valgrind not found; install it (e.g. apt install valgrind)".to_owned())?;
        run_c_tests(&[Variant {
            wrapper: vec!["valgrind", "--quiet", "--error-exitcode=99", "--leak-check=no", "--trace-children=no"],
            ..base("valgrind")
        }])
    } else {
        Err("memcheck needs macOS (Guard Malloc) or Linux (valgrind)".to_owned())
    }
}

/// The library's unit tests under Miri, which detects undefined behaviour in
/// unsafe code (and data races between Rust threads). Isolation is off
/// because minting key ids reads the clock and OS randomness. SHA-2 uses its
/// portable code: Miri cannot run the CPU's SHA instructions (Miri builds in
/// its own target directory, so normal builds keep them).
fn miri() -> Result<(), String> {
    let n = nightly()?;
    let mut flags = env::var("MIRIFLAGS").unwrap_or_default();
    flags.push_str(" -Zmiri-disable-isolation");
    let mut rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    rustflags.push_str(r#" --cfg sha2_backend="soft""#);
    run(
        n.cargo()
            .env("MIRIFLAGS", flags.trim())
            .env("RUSTFLAGS", rustflags.trim())
            .args(["miri", "test", "--lib", "--package", PACKAGE]),
        "cargo miri test",
    )
}

/// The C tests against a library built with ThreadSanitizer. The Rust code
/// and its std are instrumented (-Zbuild-std), so races inside the library
/// are seen, not only races in the C test code.
fn tsan() -> Result<(), String> {
    let n = nightly()?;
    let target_dir = root().join("target/tsan");
    run(
        n.cargo()
            .env("RUSTFLAGS", "-Zsanitizer=thread")
            .args(["build", "-Zbuild-std", "--package", PACKAGE, "--target", &n.host, "--target-dir"])
            .arg(&target_dir),
        "cargo build (tsan)",
    )?;
    let lib_dir = target_dir.join(&n.host).join("debug");
    link_versioned(&lib_dir)?;

    // A process may contain one TSan runtime. On macOS the instrumented
    // cdylib already links Rust's; the C test must use that one, not clang's.
    // Elsewhere Rust links the runtime only into executables, so clang's is it.
    let link = if cfg!(target_os = "macos") {
        let rt_dir = n.sysroot.join("lib/rustlib").join(&n.host).join("lib");
        vec![
            rt_dir.join("librustc-nightly_rt.tsan.dylib").display().to_string(),
            format!("-Wl,-rpath,{}", rt_dir.display()),
        ]
    } else {
        vec!["-fsanitize=thread".to_owned()]
    };
    run_c_tests(&[Variant {
        name: "tsan",
        lib_dir,
        compile: vec!["-O1", "-g", "-fsanitize=thread"],
        link,
        ..Variant::default()
    }])
}

// ---------------------------------------------------------------------------
// The C benchmark harness
// ---------------------------------------------------------------------------

/// Builds the release library and benches/c/bench.c (-O2) against it, then
/// runs the harness with `args`. Release, not debug: these are the numbers
/// clients get.
fn bench(args: &[String]) -> Result<(), String> {
    run(
        Command::new(env!("CARGO")).current_dir(root()).args(["build", "--release", "--package", PACKAGE]),
        "cargo build --release",
    )?;
    let lib_dir = root().join("target/release");
    link_versioned(&lib_dir)?;
    let out_dir = root().join("target/c-bench");
    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let exe = out_dir.join("bench");
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    run(
        Command::new(&cc)
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread", "-I"])
            .arg(include_dir())
            .arg(root().join("benches/c/bench.c"))
            .arg("-L")
            .arg(&lib_dir)
            .arg(format!("-l{LIB}"))
            .arg(format!("-Wl,-rpath,{}", lib_dir.display()))
            .arg("-o")
            .arg(&exe),
        "cc bench",
    )?;
    run(Command::new(&exe).args(args), "bench")
}

// ---------------------------------------------------------------------------
// Running the C tests
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Variant {
    name: &'static str,
    /// Where the library to link against lives.
    lib_dir: PathBuf,
    compile: Vec<&'static str>,
    link: Vec<String>,
    /// Environment for running each test (e.g. Guard Malloc).
    run_env: Vec<(&'static str, &'static str)>,
    /// A command each test runs under (e.g. valgrind and its flags).
    wrapper: Vec<&'static str>,
}

fn run_c_tests(variants: &[Variant]) -> Result<(), String> {
    // The tests, and the examples, which are built and run the same way so
    // they cannot fall behind the headers.
    let mut sources: Vec<PathBuf> = Vec::new();
    for dir in ["tests/c", "examples/c"] {
        let found = fs::read_dir(root().join(dir)).map_err(|e| format!("cannot read {dir}: {e}"))?;
        sources.extend(found.map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "c")));
    }
    sources.sort_by_key(|p| p.file_name().map(|n| n.to_owned()));
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_owned());

    let mut failed = Vec::new();
    for v in variants {
        let out_dir = root().join("target/c-tests").join(v.name);
        fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
        for src in &sources {
            let name = src.file_stem().unwrap().to_string_lossy().into_owned();
            let obj = out_dir.join(format!("{name}.o"));
            let exe = out_dir.join(&name);
            let label = format!("{}/{name}", v.name);

            // Compile and link separately: link flags differ from compile
            // flags for TSan (see `tsan`).
            let compiled = run(
                Command::new(&cc)
                    .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", "-c"])
                    .args(&v.compile)
                    .arg("-I")
                    .arg(include_dir())
                    .arg("-I")
                    .arg(src.parent().unwrap())
                    .arg(src)
                    .arg("-o")
                    .arg(&obj),
                &format!("cc {label}"),
            )
            .and_then(|()| {
                run(
                    Command::new(&cc)
                        .arg(&obj)
                        .arg("-pthread")
                        .args(&v.link)
                        .arg("-L")
                        .arg(&v.lib_dir)
                        .arg(format!("-l{LIB}"))
                        .arg(format!("-Wl,-rpath,{}", v.lib_dir.display()))
                        .arg("-o")
                        .arg(&exe),
                    &format!("link {label}"),
                )
            });
            if let Err(e) = compiled {
                println!("FAIL {label} ({e})");
                failed.push(label);
                continue;
            }
            // LeakSanitizer is not available everywhere (e.g. macOS arm64).
            let mut cmd = match v.wrapper.split_first() {
                Some((tool, args)) => {
                    let mut c = Command::new(tool);
                    c.args(args).arg(&exe);
                    c
                }
                None => Command::new(&exe),
            };
            let ran = cmd
                .envs(v.run_env.iter().copied())
                .env("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1")
                .env("TSAN_OPTIONS", "halt_on_error=1")
                .status()
                .map_err(|e| format!("cannot run {label}: {e}"))?;
            if ran.success() {
                println!("ok   {label}");
            } else {
                println!("FAIL {label} ({ran})");
                failed.push(label);
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("{} C test(s) failed: {failed:?}", failed.len()))
    }
}

// ---------------------------------------------------------------------------
// Interop with the Go implementation
// ---------------------------------------------------------------------------

/// Rust and Go each check what the other produced: `export` (Rust) writes
/// rust.json; interop/go/interop_test.go, placed into citius-server's
/// software provider package with `go test -overlay`, verifies and decrypts
/// it and writes go.json; `import` (Rust) checks that. The checkout is found
/// at `CITIUS_SERVER_DIR` (default ../citius-server) and is not modified.
fn interop() -> Result<(), String> {
    let server = env::var_os("CITIUS_SERVER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("../citius-server"));
    let package = server.join("internal/provider/software");
    if !package.is_dir() {
        return Err(format!("no citius-server software provider at {}; set CITIUS_SERVER_DIR", package.display()));
    }
    let dir = root().join("target/interop");
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for f in ["rust.json", "go.json"] {
        let _ = fs::remove_file(dir.join(f));
    }
    let rust_tests = |name: &str| {
        let mut c = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        c.current_dir(root())
            .env("AGC_INTEROP_DIR", &dir)
            .args(["test", "--quiet", "--lib", "--package", PACKAGE, "--", "--ignored", "--exact", "--nocapture"])
            .arg(format!("adapters::providers::interop::{name}"));
        c
    };
    run(&mut rust_tests("export"), "interop export (Rust)")?;

    let overlay = dir.join("overlay.json");
    let target = package.join("zz_agilecrypto_interop_test.go");
    let source = root().join("interop/go/interop_test.go");
    let json = format!(
        "{{\"Replace\": {{{}: {}}}}}",
        json_quote(&target.to_string_lossy()),
        json_quote(&source.to_string_lossy())
    );
    fs::write(&overlay, json).map_err(|e| format!("{}: {e}", overlay.display()))?;
    let commit = output(Command::new("git").arg("-C").arg(&server).args(["rev-parse", "--short", "HEAD"]), "git")?;
    println!("interop: citius-server at {}", commit.trim());
    run(
        Command::new("go")
            .current_dir(&server)
            .env("AGC_INTEROP_DIR", &dir)
            .args(["test", "-count=1", "-v", "-run", "^TestRustInterop$"])
            .arg(format!("-overlay={}", overlay.display()))
            .arg("./internal/provider/software"),
        "interop check (Go)",
    )?;
    run(&mut rust_tests("import"), "interop import (Rust)")
}

fn json_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

// ---------------------------------------------------------------------------
// Installing
// ---------------------------------------------------------------------------

/// Installs the release library for C projects:
///
///   DIR/lib/libagilecrypto.<major>.dylib  (libagilecrypto.so.<major> on Linux)
///   DIR/lib/libagilecrypto.dylib          -> the versioned file, for linking
///   DIR/lib/libagilecrypto.a
///   DIR/include/agc/*.h                   the headers, at HEADERS_PIN
///   DIR/lib/pkgconfig/agilecrypto.pc      pkg-config --cflags --libs agilecrypto
///   DIR/lib/cmake/agilecrypto/            find_package(agilecrypto) -> agilecrypto::agilecrypto
///
/// The headers go under include/agc, so programs include them as
/// "agilecrypto.h" with -I.../include/agc, as citius-c-api's own
/// agilecrypto.pc.in does.
fn install(args: &[String]) -> Result<(), String> {
    let prefix = match args {
        [flag, dir] if flag == "--prefix" => PathBuf::from(dir),
        _ => return Err("usage: cargo xtask install --prefix DIR".into()),
    };
    // Builds the release library and reports what the static library needs
    // from the system (rustc's own list, so it is right on every platform).
    let report = Command::new(env!("CARGO"))
        .current_dir(root())
        .args(["rustc", "--release", "--lib", "--package", PACKAGE, "--crate-type", "cdylib,staticlib"])
        .args(["--", "--print", "native-static-libs"])
        .output()
        .map_err(|e| format!("cannot run cargo rustc: {e}"))?;
    if !report.status.success() {
        return Err(format!("cargo rustc --release failed:\n{}", String::from_utf8_lossy(&report.stderr)));
    }
    let static_libs = String::from_utf8_lossy(&report.stderr)
        .lines()
        .find_map(|l| l.split("native-static-libs: ").nth(1).map(str::trim).map(str::to_owned))
        .ok_or("rustc did not report the static library's native dependencies")?;
    let built = root().join("target/release");
    let lib = prefix.join("lib");
    let include = prefix.join("include/agc");
    let pkgconfig = lib.join("pkgconfig");
    let cmake = lib.join("cmake").join(LIB);
    for d in [&lib, &include, &pkgconfig, &cmake] {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let copy = |from: &Path, to: &Path| fs::copy(from, to).map(|_| ()).map_err(|e| format!("{}: {e}", to.display()));

    // The shared library under its versioned name, the dev link to it.
    let versioned = versioned_cdylib_name()?;
    copy(&cdylib(&built), &lib.join(&versioned))?;
    let dev = lib.join(cdylib(&built).file_name().unwrap());
    let _ = fs::remove_file(&dev);
    std::os::unix::fs::symlink(&versioned, &dev).map_err(|e| format!("{}: {e}", dev.display()))?;
    copy(&built.join(format!("lib{LIB}.a")), &lib.join(format!("lib{LIB}.a")))?;

    for entry in fs::read_dir(include_dir()).map_err(|e| format!("{}: {e}", include_dir().display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("h") {
            copy(&path, &include.join(path.file_name().unwrap()))?;
        }
    }

    let version = cargo_package_version()?;
    fs::write(
        pkgconfig.join(format!("{LIB}.pc")),
        format!(
            "prefix={prefix}\nlibdir=${{prefix}}/lib\nincludedir=${{prefix}}/include\n\n\
             Name: {LIB}\nDescription: Abstract Cryptographic API, C binding (Rust implementation)\n\
             Version: {version}\nLibs: -L${{libdir}} -l{LIB}\nLibs.private: {static_libs}\n\
             Cflags: -I${{includedir}}/agc\n",
            prefix = prefix.display(),
        ),
    )
    .map_err(|e| e.to_string())?;

    fs::write(
        cmake.join(format!("{LIB}Config.cmake")),
        format!(
            "# find_package({LIB}) -> the imported target {LIB}::{LIB}.\n\
             get_filename_component(_agc_prefix \"${{CMAKE_CURRENT_LIST_DIR}}/../../..\" ABSOLUTE)\n\
             if(NOT TARGET {LIB}::{LIB})\n\
             \x20 add_library({LIB}::{LIB} SHARED IMPORTED)\n\
             \x20 set_target_properties({LIB}::{LIB} PROPERTIES\n\
             \x20   IMPORTED_LOCATION \"${{_agc_prefix}}/lib/{versioned}\"\n\
             \x20   IMPORTED_SONAME \"{soname}\"\n\
             \x20   INTERFACE_INCLUDE_DIRECTORIES \"${{_agc_prefix}}/include/agc\")\n\
             endif()\n\
             unset(_agc_prefix)\n",
            soname = if cfg!(target_os = "macos") { format!("@rpath/{versioned}") } else { versioned.clone() },
        ),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        cmake.join(format!("{LIB}ConfigVersion.cmake")),
        format!(
            "# Compatible within one major version: the ABI breaks only across majors.\n\
             set(PACKAGE_VERSION \"{version}\")\n\
             string(REGEX MATCH \"^[0-9]+\" _agc_major \"${{PACKAGE_FIND_VERSION}}\")\n\
             if(PACKAGE_FIND_VERSION VERSION_GREATER PACKAGE_VERSION OR NOT _agc_major STREQUAL \"{major}\")\n\
             \x20 set(PACKAGE_VERSION_COMPATIBLE FALSE)\n\
             else()\n\
             \x20 set(PACKAGE_VERSION_COMPATIBLE TRUE)\n\
             \x20 if(PACKAGE_FIND_VERSION STREQUAL PACKAGE_VERSION)\n\
             \x20   set(PACKAGE_VERSION_EXACT TRUE)\n\
             \x20 endif()\n\
             endif()\n\
             unset(_agc_major)\n",
            major = major_version()?,
        ),
    )
    .map_err(|e| e.to_string())?;
    println!("install: {} under {}", versioned, prefix.display());
    Ok(())
}

fn cargo_package_version() -> Result<String, String> {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).map_err(|e| format!("Cargo.toml: {e}"))?;
    manifest
        .lines()
        .find_map(|l| l.strip_prefix("version = \"").and_then(|v| v.strip_suffix('"')))
        .map(str::to_owned)
        .ok_or_else(|| "Cargo.toml has no version".into())
}
