use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

/// Header functions that are not implemented yet, one name per line.
const SKIP_FILE: &str = "abi_skip.txt";

fn main() {
    println!("cargo:rerun-if-changed={SKIP_FILE}");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // bindgen::Builder is the main part that does the magic
    let bindings = bindgen::Builder::default()
        .header("include/agc_key.h")
        .clang_arg("-Iinclude")
        .allowlist_item("agc_.*|AGC_.*")
        // Let clang evaluate macros bindgen cannot parse itself, e.g. `((agc_rc)-2)`
        .clang_macro_fallback()
        .clang_macro_fallback_build_dir(&out_path)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file
    bindings.write_to_file(out_path.join("bindings.rs")).expect("Couldn't write bindings");

    // Every function the headers declare is either checked against its
    // implementation in `crate::exports`, or listed in the skip file.
    let functions = header_functions(&bindings.to_string());
    let skip = read_skip_list();

    for name in &skip {
        if !functions.iter().any(|(f, _)| f == name) {
            panic!("{SKIP_FILE}: `{name}` is not declared in the headers");
        }
    }

    let mut checks = String::new();
    for (name, arity) in &functions {
        if skip.contains(name) {
            write_skipped_check(&mut checks, name);
        } else {
            write_signature_check(&mut checks, name, *arity);
        }
    }
    fs::write(out_path.join("abi_checks.rs"), checks).expect("Couldn't write abi checks");
}

/// Name and parameter count of every function in the bindings' `extern "C"` blocks.
fn header_functions(bindings: &str) -> Vec<(String, usize)> {
    let file = syn::parse_file(bindings).expect("bindings.rs is not valid Rust");
    let mut functions = Vec::new();
    for item in file.items {
        if let syn::Item::ForeignMod(block) = item {
            for foreign in block.items {
                if let syn::ForeignItem::Fn(f) = foreign {
                    functions.push((f.sig.ident.to_string(), f.sig.inputs.len()));
                }
            }
        }
    }
    functions
}

fn read_skip_list() -> BTreeSet<String> {
    let text = fs::read_to_string(SKIP_FILE).unwrap_or_else(|e| panic!("Couldn't read {SKIP_FILE}: {e}"));
    text.lines()
        .map(|line| line.split('#').next().unwrap().trim())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The header's declaration and our definition must coerce to the same
/// function pointer type, because all elements of an array share one type.
fn write_signature_check(out: &mut String, name: &str, arity: usize) {
    let params = vec!["_"; arity].join(", ");
    writeln!(
        out,
        "const _: () = {{
    let _ = [
        crate::bindings::{name} as unsafe extern \"C\" fn({params}) -> _,
        crate::exports::{name},
    ];
}};"
    )
    .unwrap();
}

/// Fails once `crate::exports` defines `name`: two glob imports then provide
/// it and the use below becomes ambiguous. Keeps the skip file from going stale.
fn write_skipped_check(out: &mut String, name: &str) {
    writeln!(
        out,
        "mod skipped_{name} {{
    mod remove_this_name_from_abi_skip_txt {{
        pub const {name}: () = ();
    }}
    use remove_this_name_from_abi_skip_txt::*;
    use crate::exports::*;
    const _: () = {{
        let _ = {name};
    }};
}}"
    )
    .unwrap();
}
