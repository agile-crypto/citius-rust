//! The dependency rules of the layered, domain-driven design, checked on the
//! source. With a single crate the compiler cannot enforce them, so this test
//! does what Go's package system and import graph do for citius-core:
//!
//! - a domain uses `domain::core`, itself, and the generated API types
//!   (`proto`, the shared vocabulary Go's core gets from citius-api-go);
//! - `domain::core` uses nothing outside itself;
//! - nothing below `ffi` knows the C types (`bindings`) or `ffi`;
//! - `adapters` implement domain interfaces and know nothing of `app`.
//!
//! Every path the code names that starts with `crate::` is checked, in `use`
//! declarations and inline. `super::super` is rejected in domains so that a
//! path cannot climb out of its domain unchecked.

use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");

/// Every `crate::...` and `super::super...` path in one file, as strings.
#[derive(Default)]
struct Paths(Vec<String>);

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

impl<'ast> Visit<'ast> for Paths {
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
    let mut files = Vec::new();
    rust_files(&Path::new(SRC).join(layer), &mut files);
    assert!(!files.is_empty(), "no sources under src/{layer}");
    let mut found = Vec::new();
    for file in files {
        let ast = syn::parse_file(&fs::read_to_string(&file).unwrap()).unwrap();
        let mut paths = Paths::default();
        paths.visit_file(&ast);
        let rel = file.strip_prefix(SRC).unwrap().display().to_string();
        found.extend(paths.0.into_iter().map(|p| (rel.clone(), p)));
    }
    found
}

/// Fails listing every path in `layer` that `allowed` rejects.
fn check(layer: &str, allowed: impl Fn(&str, &str) -> bool) {
    let violations: Vec<String> = paths_in(layer)
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
        is_below(path, "crate::domain::core") || is_below(path, &own) || is_below(path, "crate::proto")
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
        is_below(path, "crate::domain") || is_below(path, "crate::adapters") || is_below(path, "crate::proto")
    });
}

#[test]
fn the_checker_sees_violations() {
    // Guards against a checker that silently finds nothing.
    let paths = paths_in("ffi");
    assert!(paths.iter().any(|(_, p)| is_below(p, "crate::bindings")), "expected ffi to use bindings");
    assert!(paths.iter().any(|(_, p)| p == "crate::domain::core::ScopeKind"), "expected a nested use path");
}
