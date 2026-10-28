use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

/// Header functions that are not implemented yet, one name per line.
const SKIP_FILE: &str = "abi_skip.txt";

/// The headers are owned by citius-c-api; we read them in place instead of
/// keeping a copy. HEADERS_PIN names the revision we implement against.
const DEFAULT_INCLUDE_DIR: &str = "../citius-c-api/include/agc";

fn main() {
    println!("cargo:rerun-if-changed={SKIP_FILE}");
    println!("cargo:rerun-if-env-changed=AGC_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=AGC_DESCRIPTOR");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let include_dir = env::var("AGC_INCLUDE_DIR").unwrap_or_else(|_| DEFAULT_INCLUDE_DIR.to_owned());

    // The API's protobuf types, from the descriptor citius-c-api pins next
    // to its headers (conformance/api_descriptor.binpb).
    let descriptor = env::var("AGC_DESCRIPTOR")
        .unwrap_or_else(|_| format!("{include_dir}/../../conformance/api_descriptor.binpb"));
    generate_protos(&descriptor, &out_path);

    // bindgen::Builder is the main part that does the magic
    let bindings = bindgen::Builder::default()
        .header(format!("{include_dir}/agilecrypto.h"))
        .clang_arg(format!("-I{include_dir}"))
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
    // implementation in `crate::ffi::exports`, or listed in the skip file.
    let functions = header_functions(&bindings.to_string());
    let skip = read_skip_list();

    for name in &skip {
        if !functions.iter().any(|(f, _)| f == name) {
            panic!("{SKIP_FILE}: `{name}` is not declared in the headers");
        }
    }

    // The full list, for tools that compare it with what the library exports.
    let names: Vec<&str> = functions.iter().map(|(f, _)| f.as_str()).collect();
    fs::write(out_path.join("header_functions.txt"), names.join("\n") + "\n")
        .expect("Couldn't write header function list");

    let types_header = fs::read_to_string(format!("{include_dir}/agc_types.h")).expect("Couldn't read agc_types.h");
    fs::write(out_path.join("rc_table.rs"), rc_table(&types_header)).expect("Couldn't write rc table");

    let enum_file = enum_helpers(&bindings.to_string(), &functions);
    fs::write(out_path.join("enum_helpers.rs"), enum_file).expect("Couldn't write enum helpers");

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

/// Rust types (prost) and their protobuf-JSON form (pbjson) for every
/// `caas.*` file in the descriptor. `google.protobuf` maps to pbjson_types;
/// `buf.validate` and `google.api` carry only annotations and are dropped.
fn generate_protos(descriptor: &str, out_path: &std::path::Path) {
    use prost::Message as _;
    println!("cargo:rerun-if-changed={descriptor}");
    let bytes = fs::read(descriptor).unwrap_or_else(|e| panic!("Couldn't read {descriptor}: {e}"));
    let mut fds = prost_types::FileDescriptorSet::decode(bytes.as_slice()).expect("descriptor is not a FileDescriptorSet");
    // prost needs the google.protobuf definitions to resolve the extern path.
    fds.file.retain(|f| f.package().starts_with("caas.") || f.package() == "google.protobuf");

    let proto_out = out_path.join("proto");
    fs::create_dir_all(&proto_out).unwrap();
    prost_build::Config::new()
        .out_dir(&proto_out)
        // Replaces prost's default mapping to prost_types (pbjson's recipe).
        .compile_well_known_types()
        .extern_path(".google.protobuf", "::pbjson_types")
        // Maps as BTreeMap: encoding is deterministic (sorted keys), which
        // canonical metadata needs.
        .btree_map(["."])
        .compile_fds(fds)
        .expect("prost code generation failed");
    pbjson_build::Builder::new()
        .out_dir(&proto_out)
        .btree_map(["."])
        .register_descriptors(&bytes)
        .expect("pbjson cannot read the descriptor")
        .build(&[".caas"])
        .expect("pbjson code generation failed");
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

/// A table of every return code agc_types.h defines (`AGC_OK`, `AGC_ERR_*`)
/// with its name and message, so neither is maintained by hand. The value
/// comes from the bindings (the compiler checks the name exists); the
/// message is the macro's trailing comment, or for crypto codes (whose
/// comment is only "wire value N") the name in words.
fn rc_table(types_header: &str) -> String {
    let mut out = String::from(
        "pub const RC_TABLE: &[(crate::bindings::agc_rc, &::std::ffi::CStr, &::std::ffi::CStr)] = &[\n",
    );
    for line in types_header.lines() {
        let Some(rest) = line.strip_prefix("#define ") else { continue };
        let Some((name, rest)) = rest.split_once(' ') else { continue };
        if !rest.trim_start().starts_with("((agc_rc)") {
            continue;
        }
        let comment = rest.split_once("/*").map(|(_, c)| c.trim_end().trim_end_matches("*/").trim());
        let message = match (name, comment) {
            ("AGC_OK", _) => "success".to_owned(),
            (n, _) if n.starts_with("AGC_ERR_CRYPTO_") => {
                n["AGC_ERR_CRYPTO_".len()..].to_lowercase().replace('_', " ")
            }
            (_, Some(c)) => c.to_owned(),
            (n, None) => panic!("agc_types.h: {n} has no comment to use as its message"),
        };
        writeln!(
            out,
            "    (crate::bindings::{name} as crate::bindings::agc_rc, c{name:?}, c{message:?}),"
        )
        .unwrap();
    }
    out.push_str("];\n");
    out
}

/// The `agc_<enum>_name` / `agc_<enum>_from_name` pair for every enum the
/// headers declare one for: a `(value, name)` table and the two exports on
/// top of it. A name is the enumerator without `AGC_`, which is the proto's
/// name (the same rule as citius-c-api/tools/gen_agc_types.py).
///
/// Enumerators are picked by their declared type, not by name prefix, so
/// `agc_signature_scope_kind_*` cannot land in `agc_signature_scope`.
fn enum_helpers(bindings: &str, functions: &[(String, usize)]) -> String {
    let declared: BTreeSet<&str> = functions.iter().map(|(f, _)| f.as_str()).collect();
    let enums: Vec<&str> = declared
        .iter()
        .filter_map(|f| f.strip_suffix("_from_name"))
        .filter(|base| declared.contains(format!("{base}_name").as_str()))
        .collect();

    let file = syn::parse_file(bindings).expect("bindings.rs is not valid Rust");
    let mut out = String::new();
    // For the tests: every enum's name and from_name, applied to its table.
    let mut round_trips = String::from(
        "#[cfg(test)]\npub(super) type RoundTrip<'a> = &'a mut dyn FnMut(usize) -> bool;\n\
         #[cfg(test)]\npub(super) fn round_trip_all(check: &mut dyn FnMut(&str, usize, RoundTrip)) {\n",
    );
    for base in enums {
        let prefix = format!("{base}_AGC_");
        let mut values = Vec::new();
        for item in &file.items {
            let syn::Item::Const(c) = item else { continue };
            let syn::Type::Path(ty) = &*c.ty else { continue };
            let ident = c.ident.to_string();
            if ty.path.is_ident(base) && ident.starts_with(&prefix) {
                values.push((ident.clone(), ident[prefix.len()..].to_owned()));
            }
        }
        assert!(!values.is_empty(), "no enumerators of type {base} in the bindings");

        let table = format!("{}_NAMES", base.to_uppercase());
        writeln!(
            round_trips,
            "    check({base:?}, {table}.len(), &mut |i| {{
        let (value, name) = {table}[i];
        let mut back: {base} = 0;
        // SAFETY: name is a static C string, back a live local.
        let rc = unsafe {{ {base}_from_name(name.as_ptr(), &mut back) }};
        // SAFETY: {base}_name returns a static C string.
        let named = unsafe {{ ::std::ffi::CStr::from_ptr({base}_name(value)) }};
        rc == 0 && back == value && named == name
    }});"
        )
        .unwrap();
        writeln!(out, "const {table}: &[({base}, &::std::ffi::CStr)] = &[").unwrap();
        for (constant, name) in &values {
            writeln!(out, "    ({constant}, c{name:?}),").unwrap();
        }
        writeln!(
            out,
            "];

#[unsafe(no_mangle)]
pub extern \"C\" fn {base}_name(v: {base}) -> *const ::std::ffi::c_char {{
    enum_name({table}, v)
}}

#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn {base}_from_name(name: *const ::std::ffi::c_char, out: *mut {base}) -> agc_rc {{
    // SAFETY: the header's contract: name is NULL or a C string, out is NULL or writable.
    unsafe {{ enum_from_name({table}, name, out) }}
}}
"
        )
        .unwrap();
    }
    round_trips.push_str("}\n");
    out + &round_trips
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
        crate::ffi::exports::{name},
    ];
}};"
    )
    .unwrap();
}

/// Fails once `crate::ffi::exports` defines `name`: two glob imports then provide
/// it and the use below becomes ambiguous. Keeps the skip file from going stale.
fn write_skipped_check(out: &mut String, name: &str) {
    writeln!(
        out,
        "mod skipped_{name} {{
    mod remove_this_name_from_abi_skip_txt {{
        pub const {name}: () = ();
    }}
    use remove_this_name_from_abi_skip_txt::*;
    use crate::ffi::exports::*;
    const _: () = {{
        let _ = {name};
    }};
}}"
    )
    .unwrap();
}
