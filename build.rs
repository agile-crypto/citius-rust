use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use quote::ToTokens as _;

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
    let table = rc_table(&types_header);
    check_rc_table_complete(&bindings.to_string(), &table);
    fs::write(out_path.join("rc_table.rs"), table).expect("Couldn't write rc table");

    let enum_file = enum_helpers(&bindings.to_string(), &functions);
    fs::write(out_path.join("enum_helpers.rs"), enum_file).expect("Couldn't write enum helpers");

    let proto_api = fs::read_to_string(out_path.join("proto/caas.crypto.v1.rs")).expect("Couldn't read the API protos");
    let algorithms = algorithm_params(&bindings.to_string(), &proto_api);
    fs::write(out_path.join("algorithm_params.rs"), algorithms).expect("Couldn't write algorithm params");

    set_library_name(&bindings.to_string());

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

/// rc_table reads agc_types.h as text and skips lines it does not recognise,
/// so a reformatted header could silently drop codes from agc_rc_name and
/// agc_rc_message. Every result code the bindings define (AGC_OK and
/// AGC_ERR_*) must be in the table.
fn check_rc_table_complete(bindings: &str, table: &str) {
    let file = syn::parse_file(bindings).expect("bindings.rs is not valid Rust");
    let missing: Vec<String> = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Const(c) => Some(c.ident.to_string()),
            _ => None,
        })
        .filter(|n| n == "AGC_OK" || n.starts_with("AGC_ERR_"))
        .filter(|n| !table.contains(&format!("crate::bindings::{n} as")))
        .collect();
    assert!(missing.is_empty(), "agc_types.h: result codes missing from the rc table (format changed?): {missing:?}");
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

/// The arms of `AlgorithmDetails.algorithm` whose C struct is not a field-by-field copy of
/// the proto message (strings, slices, presence flags, nested arrays). Hand-written in
/// src/ffi/translation/algorithm.rs.
const IRREGULAR_ALGORITHM_ARMS: &[&str] =
    &["gost3410", "sp800_108_kdf", "tls12", "kmac", "gost3411", "poly1305", "custom", "gost28147", "hybrid"];

/// `fill_regular_arm`: for each arm of the C `agc_algorithm_params` union whose struct has
/// exactly the proto message's fields, in order, all scalar, a field-by-field copy from
/// the prost type into the union. Arms are paired by name (union field `aes_gcm` <->
/// oneof variant `AesGcm`); the kind constant is the proto field number, as agc_algorithm_params.h
/// promises. Every other arm must be listed in IRREGULAR_ALGORITHM_ARMS, so a header or proto
/// change that breaks a pairing fails the build instead of dropping a field.
fn algorithm_params(bindings: &str, proto: &str) -> String {
    let c = syn::parse_file(bindings).expect("bindings.rs is not valid Rust");
    let p = syn::parse_file(proto).expect("the API protos are not valid Rust");

    let c_struct = |name: &str| -> Option<Vec<(String, String)>> {
        c.items.iter().find_map(|i| match i {
            syn::Item::Struct(s) if s.ident == name => Some(fields(&s.fields)),
            _ => None,
        })
    };
    let c_union = c
        .items
        .iter()
        .find_map(|i| match i {
            syn::Item::Union(u) if u.ident == "agc_algorithm_params__bindgen_ty_1" => Some(&u.fields),
            _ => None,
        })
        .expect("no agc_algorithm_params union in the bindings");
    let arms: Vec<(String, String)> =
        c_union.named.iter().map(|f| (f.ident.as_ref().unwrap().to_string(), type_name(&f.ty))).collect();

    // The oneof's variants, and each message's fields with their prost kind.
    let oneof = find_in_mod(&p.items, "algorithm_details", "Algorithm").expect("no AlgorithmDetails.algorithm oneof");
    let syn::Item::Enum(oneof) = oneof else { unreachable!() };
    let message = |name: &str| -> Option<Vec<(String, String)>> {
        p.items.iter().find_map(|i| match i {
            syn::Item::Struct(s) if s.ident == name => Some(
                s.fields
                    .iter()
                    .map(|f| {
                        let kind = f
                            .attrs
                            .iter()
                            .find(|a| a.path().is_ident("prost"))
                            .map(|a| a.meta.to_token_stream().to_string())
                            .unwrap_or_default();
                        (f.ident.as_ref().unwrap().to_string(), kind)
                    })
                    .collect(),
            ),
            _ => None,
        })
    };

    let mut out = String::from(
        "/// Fills the arm of `u` for a regular algorithm (generated by build.rs). Returns the C\n\
         /// kind, or None for an arm written by hand.\n\
         pub(super) fn fill_regular_arm(a: &Algorithm, u: &mut agc_algorithm_params) -> Option<agc_algorithm_kind> {\n\
         \x20   // Writing a union member is safe; the returned kind names the member written.\n\
         \x20   match a {\n",
    );
    let mut regular = 0;
    for (arm, ctype) in &arms {
        let variant = camel(arm);
        let Some(v) = oneof.variants.iter().find(|v| v.ident.to_string().eq_ignore_ascii_case(&variant.replace('_', ""))) else {
            panic!("agc_algorithm_params arm `{arm}` has no AlgorithmDetails variant");
        };
        if IRREGULAR_ALGORITHM_ARMS.contains(&arm.as_str()) {
            continue;
        }
        let syn::Fields::Unnamed(inner) = &v.fields else { panic!("variant {} has no message", v.ident) };
        let msg = type_name(&inner.unnamed[0].ty);
        let msg = msg.rsplit("::").next().unwrap().to_owned();
        let cf = c_struct(ctype).unwrap_or_else(|| panic!("no C struct {ctype}"));
        let pf = message(&msg).unwrap_or_else(|| panic!("no proto message {msg}"));
        let cn: Vec<&str> = cf.iter().map(|(n, _)| n.as_str()).collect();
        let pn: Vec<&str> = pf.iter().map(|(n, _)| n.trim_start_matches("r#")).collect();
        assert_eq!(cn, pn, "arm `{arm}`: C {ctype} and proto {msg} differ; list it in IRREGULAR_ALGORITHM_ARMS");
        let kind_const = format!("agc_algorithm_kind_AGC_ALGORITHM_{}", arm.to_uppercase());
        writeln!(out, "        Algorithm::{}(m) => {{", v.ident).unwrap();
        if cf.is_empty() {
            writeln!(out, "            let _ = m;").unwrap();
        }
        for ((name, ctype_f), (_, kind)) in cf.iter().zip(&pf) {
            let value = if kind.contains("enumeration") {
                // C enums are u32 in the bindings, proto enums i32; values are the same.
                format!("m.{name} as u32")
            } else if kind.contains("bool") {
                format!("::std::ffi::c_int::from(m.{name})")
            } else if kind.contains("uint32") || kind.contains("uint64") {
                format!("m.{name}")
            } else {
                panic!("arm `{arm}` field `{name}` ({ctype_f}) has prost kind {kind}: not scalar");
            };
            writeln!(out, "            u.u.{arm}.{name} = {value};").unwrap();
        }
        writeln!(out, "            Some({kind_const})\n        }}").unwrap();
        regular += 1;
    }
    out.push_str("        _ => None,\n    }\n}\n");
    assert_eq!(regular + IRREGULAR_ALGORITHM_ARMS.len(), arms.len(), "every arm is regular or listed as irregular");
    out
}

fn fields(f: &syn::Fields) -> Vec<(String, String)> {
    f.iter().map(|f| (f.ident.as_ref().unwrap().to_string(), type_name(&f.ty))).collect()
}

fn type_name(t: &syn::Type) -> String {
    t.to_token_stream().to_string().replace(' ', "")
}

/// `name` inside `pub mod module`.
fn find_in_mod<'a>(items: &'a [syn::Item], module: &str, name: &str) -> Option<&'a syn::Item> {
    items.iter().find_map(|i| match i {
        syn::Item::Mod(m) if m.ident == module => m.content.as_ref()?.1.iter().find(|i| match i {
            syn::Item::Enum(e) => e.ident == name,
            _ => false,
        }),
        _ => None,
    })
}

fn camel(snake: &str) -> String {
    snake.split('_').map(|w| w[..1].to_uppercase() + &w[1..]).collect()
}

/// The shared library's versioned name, from the crate's major version: on
/// Linux the soname `libagilecrypto.so.<major>`, on macOS the install name
/// `@rpath/libagilecrypto.<major>.dylib`. The crate's major version must be
/// the headers' AGC_API_VERSION_MAJOR, so a library and the headers it
/// implements cannot disagree about the ABI.
fn set_library_name(bindings: &str) {
    let major: u32 = env::var("CARGO_PKG_VERSION_MAJOR").unwrap().parse().unwrap();
    // Parsed, not matched as text: without rustfmt, bindgen's output is
    // unformatted (`pub const AGC_API_VERSION_MAJOR : u32 = 1 ;`).
    let file = syn::parse_file(bindings).expect("bindings.rs is not valid Rust");
    let header_major: u32 = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Const(c) if c.ident == "AGC_API_VERSION_MAJOR" => match &*c.expr {
                syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => i.base10_parse().ok(),
                _ => None,
            },
            _ => None,
        })
        .expect("the bindings define AGC_API_VERSION_MAJOR");
    assert_eq!(
        major, header_major,
        "Cargo.toml version {major}.x does not match the headers' AGC_API_VERSION_MAJOR {header_major}"
    );
    match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libagilecrypto.{major}.dylib"),
        Ok("linux") => println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libagilecrypto.so.{major}"),
        _ => {}
    }
}
