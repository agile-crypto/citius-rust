//! The dependency rules of the layered, domain-driven design, checked on the
//! source. With a single crate the compiler cannot enforce them, so this test
//! does what Go's package system and import graph do for citius-core:
//!
//! - a domain uses `domain::core`, itself, and the generated API types
//!   (`proto`, the shared vocabulary Go's core gets from citius-api-go);
//! - `domain::core` uses nothing outside itself;
//! - nothing below `ffi` knows the C types (`bindings`) or `ffi`;
//! - `adapters` implement domain interfaces and know nothing of `app` or
//!   `ffi`;
//! - `ffi` reaches domains and adapters only through `app`, except for its
//!   composition root, `ffi/context.rs`;
//! - the published byte formats (`wire`) know only `domain::core` and
//!   `proto`, and no domain uses them.
//!
//! Every path the code names that starts with `crate::` is checked, in `use`
//! declarations and inline. `super::super` is rejected in domains so that a
//! path cannot climb out of its domain unchecked.

use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");

/// Every `crate::...` and `super::super...` path in one file, as strings;
/// with `skip_tests`, none inside a `#[cfg(test)]` module.
#[derive(Default)]
struct Paths(Vec<String>, bool);

impl Paths {
    fn add_use(&mut self, prefix: &mut Vec<String>, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.add_use(prefix, &p.tree);
                prefix.pop();
            }
            syn::UseTree::Name(n) => self.push(prefix, &n.ident.to_string()),
            syn::UseTree::Rename(r) => self.push(prefix, &r.ident.to_string()),
            syn::UseTree::Glob(_) => self.push(prefix, "*"),
            syn::UseTree::Group(g) => g.items.iter().for_each(|t| self.add_use(prefix, t)),
        }
    }

    fn push(&mut self, prefix: &[String], last: &str) {
        let mut segs = prefix.to_vec();
        segs.push(last.to_owned());
        self.0.push(segs.join("::"));
    }
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg") && a.parse_args::<syn::Ident>().is_ok_and(|i| i == "test")
    })
}

impl<'ast> Visit<'ast> for Paths {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !(self.1 && is_cfg_test(&m.attrs)) {
            syn::visit::visit_item_mod(self, m);
        }
    }

    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        self.add_use(&mut Vec::new(), &u.tree);
    }

    fn visit_path(&mut self, p: &'ast syn::Path) {
        let segs: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
        self.0.push(segs.join("::"));
        syn::visit::visit_path(self, p);
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// (file relative to src/, path it names) for every file under `layer`.
fn paths_in(layer: &str) -> Vec<(String, String)> {
    paths_of(layer, false)
}

fn paths_of(layer: &str, skip_tests: bool) -> Vec<(String, String)> {
    let mut files = Vec::new();
    rust_files(&Path::new(SRC).join(layer), &mut files);
    assert!(!files.is_empty(), "no sources under src/{layer}");
    let mut found = Vec::new();
    for file in files {
        let ast = syn::parse_file(&fs::read_to_string(&file).unwrap()).unwrap();
        let mut paths = Paths(Vec::new(), skip_tests);
        paths.visit_file(&ast);
        let rel = file.strip_prefix(SRC).unwrap().display().to_string();
        found.extend(paths.0.into_iter().map(|p| (rel.clone(), p)));
    }
    found
}

/// Fails listing every path in `layer` that `allowed` rejects.
fn check(layer: &str, allowed: impl Fn(&str, &str) -> bool) {
    check_paths(layer, paths_in(layer), allowed)
}

fn check_paths(layer: &str, paths: Vec<(String, String)>, allowed: impl Fn(&str, &str) -> bool) {
    let violations: Vec<String> = paths
        .into_iter()
        .filter(|(file, path)| {
            (path.starts_with("crate::") || path.starts_with("super::super")) && !allowed(file, path)
        })
        .map(|(file, path)| format!("  src/{file}: {path}"))
        .collect();
    assert!(violations.is_empty(), "layering violations in src/{layer}:\n{}", violations.join("\n"));
}

/// The domain a file under src/domain/ belongs to: "domain/key/key.rs" -> "key".
fn domain_of(file: &str) -> &str {
    file.split('/').nth(1).unwrap()
}

fn is_below(path: &str, module: &str) -> bool {
    path == module || path.starts_with(&format!("{module}::"))
}

#[test]
fn domains_use_only_core_and_themselves() {
    check("domain", |file, path| {
        let own = format!("crate::domain::{}", domain_of(file));
        is_below(path, "crate::domain::core")
            || is_below(path, &own)
            || is_below(path, "crate::proto")
            || is_below(path, "crate::secret")
    });
}

#[test]
fn application_layer_does_not_know_c() {
    check("app", |_, path| {
        !is_below(path, "crate::bindings") && !is_below(path, "crate::ffi")
    });
}

#[test]
fn adapters_depend_on_domains_only() {
    check("adapters", |_, path| {
        is_below(path, "crate::domain")
            || is_below(path, "crate::adapters")
            || is_below(path, "crate::proto")
            || is_below(path, "crate::secret")
            || is_below(path, "crate::stack")
            || is_below(path, "crate::wire")
    });
}

#[test]
fn the_checker_sees_violations() {
    // Guards against a checker that silently finds nothing.
    let paths = paths_in("ffi");
    assert!(paths.iter().any(|(_, p)| is_below(p, "crate::bindings")), "expected ffi to use bindings");
    assert!(paths.iter().any(|(_, p)| p == "crate::domain::core::ScopeKind"), "expected a nested use path");
}

#[test]
fn the_published_formats_know_only_the_shared_kernel() {
    check("wire", |_, path| {
        is_below(path, "crate::wire") || is_below(path, "crate::domain::core") || is_below(path, "crate::proto")
    });
}

/// `ffi/context.rs` is the composition root: it wires adapters and domain
/// services into the application services, as do ffi's tests. Every other
/// ffi file translates C to the application layer's calls and back, and so
/// names no domain service or adapter: the domain types the application
/// services take and return come through `crate::app`.
#[test]
fn ffi_reaches_the_domain_only_through_the_application_layer() {
    check_paths("ffi", paths_of("ffi", true), |file, path| {
        file == "ffi/context.rs"
            || !(is_below(path, "crate::domain") || is_below(path, "crate::adapters"))
            || is_below(path, "crate::domain::core")
    });
}
