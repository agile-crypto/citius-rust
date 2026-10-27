//! Developer tasks that need more than `cargo test`.
//!
//!   cargo xtask test-c         build the library, check its exported symbols,
//!                              compile and run tests/c/*.c plain and with
//!                              ASan+UBSan
//!   cargo xtask check-symbols  only the symbol check
//!   cargo xtask miri           run the library's unit tests under Miri
//!   cargo xtask tsan           build the library with ThreadSanitizer and run
//!                              tests/c/*.c against it
//!   cargo xtask all            everything above
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
        "miri" => miri(),
        "tsan" => tsan(),
        "all" => test_c().and_then(|()| miri()).and_then(|()| tsan()),
        _ => Err("usage: cargo xtask <test-c|check-symbols|miri|tsan|all>".to_owned()),
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
    Ok(Built {
        lib_dir: root().join("target/debug"),
        out_dir: PathBuf::from(out_dir),
    })
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
        Variant { name: "plain", lib_dir: b.lib_dir.clone(), compile: vec!["-O1"], link: vec![] },
        Variant {
            name: "asan-ubsan",
            lib_dir: b.lib_dir,
            compile: asan.to_vec(),
            link: asan.iter().map(|f| f.to_string()).collect(),
        },
    ])
}

/// The library's unit tests under Miri, which detects undefined behaviour in
/// unsafe code (and data races between Rust threads). Isolation is off
/// because minting key ids reads the clock and OS randomness.
fn miri() -> Result<(), String> {
    let n = nightly()?;
    let mut flags = env::var("MIRIFLAGS").unwrap_or_default();
    flags.push_str(" -Zmiri-disable-isolation");
    run(
        n.cargo().env("MIRIFLAGS", flags.trim()).args(["miri", "test", "--lib", "--package", PACKAGE]),
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
    run_c_tests(&[Variant { name: "tsan", lib_dir, compile: vec!["-O1", "-g", "-fsanitize=thread"], link }])
}

// ---------------------------------------------------------------------------
// Running the C tests
// ---------------------------------------------------------------------------

struct Variant {
    name: &'static str,
    /// Where the library to link against lives.
    lib_dir: PathBuf,
    compile: Vec<&'static str>,
    link: Vec<String>,
}

fn run_c_tests(variants: &[Variant]) -> Result<(), String> {
    let mut sources: Vec<PathBuf> = fs::read_dir(root().join("tests/c"))
        .map_err(|e| format!("cannot read tests/c: {e}"))?
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "c"))
        .collect();
    sources.sort();
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
                    .arg(root().join("tests/c"))
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
            let ran = Command::new(&exe)
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
