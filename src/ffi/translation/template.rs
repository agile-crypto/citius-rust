//! Catalog records to their C form: `TemplateInfo` -> `agc_template_info`
//! and `ScopeInfo` -> `agc_scope_info` (agc_discovery_types.h). Everything
//! variable-length goes into the caller's storage through the `Packer`.

use std::ffi::c_char;

use super::{Packer, c_scope_spec, c_tribool};
use crate::app::ScopeView;
use crate::bindings::*;
use crate::domain::core::ScopeSpecification;
use crate::proto::api::{self, algorithm_details::Algorithm};

// Deprecated algorithms (3DES, Blowfish) are still catalog entries a caller
// may list, so their arms are translated too.
#[allow(deprecated)]
mod generated {
    use crate::bindings::*;
    use crate::proto::api::algorithm_details::Algorithm;
    // The field-by-field arms (build.rs `algorithm_params`).
    include!(concat!(env!("OUT_DIR"), "/algorithm_params.rs"));
}

/// Nesting deeper than this is refused when writing: a hybrid's components
/// are plain algorithms, so a catalog never needs more than two levels.
const MAX_ALGORITHM_DEPTH: usize = 4;

fn zeroed<T: crate::ffi::versioned::CStruct>() -> T {
    // SAFETY: CStruct types are valid all-zero (integers and raw pointers).
    unsafe { std::mem::zeroed() }
}

fn strs(p: &mut Packer, items: &[String]) -> (*mut *const c_char, usize) {
    let ptrs: Vec<*const c_char> = items.iter().map(|s| p.str(s)).collect();
    let slot = p.reserve_array::<*const c_char>(ptrs.len());
    p.fill_array(slot, &ptrs);
    (slot, ptrs.len())
}

/// The C form of an algorithm. `depth` guards the hybrid recursion.
pub fn c_algorithm_details(a: &api::AlgorithmDetails, p: &mut Packer, depth: usize) -> agc_algorithm_details {
    let mut c: agc_algorithm_details = zeroed();
    c.oid = p.str(&a.oid);
    c.primitive = a.primitive as u32;
    if let Some(alg) = &a.algorithm {
        c.params.kind = match generated::fill_regular_arm(alg, &mut c.params) {
            Some(kind) => kind,
            None => irregular_arm(alg, &mut c.params, p, depth),
        };
    }
    c
}

/// The arms whose C struct is not a copy of the proto message.
fn irregular_arm(a: &Algorithm, c: &mut agc_algorithm_params, p: &mut Packer, depth: usize) -> agc_algorithm_kind {
    // Writing a union member is safe; the returned kind names the member written.
    match a {
        Algorithm::Ed448(m) => {
            c.u.ed448.variant = m.variant as u32;
            c.u.ed448.context = p.bytes(&m.context);
            agc_algorithm_kind_AGC_ALGORITHM_ED448
        }
        Algorithm::Gost3410(m) => {
            c.u.gost3410.version = m.version as u32;
            c.u.gost3410.key_size_bits = m.key_size_bits;
            c.u.gost3410.parameter_set_oid = p.str(&m.parameter_set_oid);
            c.u.gost3410.digest_param_set_oid = p.str(&m.digest_param_set_oid);
            agc_algorithm_kind_AGC_ALGORITHM_GOST3410
        }
        Algorithm::Sp800108Kdf(m) => {
            c.u.sp800_108_kdf.mode = m.mode as u32;
            c.u.sp800_108_kdf.prf = m.prf as u32;
            c.u.sp800_108_kdf.derived_key_length_bytes = m.derived_key_length_bytes;
            if let Some(f) = &m.counter_format {
                c.u.sp800_108_kdf.has_counter_format = 1;
                c.u.sp800_108_kdf.counter_format =
                    agc_sp800_108_counter_format { little_endian: i32::from(f.little_endian), width_bits: f.width_bits };
            }
            c.u.sp800_108_kdf.iv_length_bytes = m.iv_length_bytes;
            agc_algorithm_kind_AGC_ALGORITHM_SP800_108_KDF
        }
        Algorithm::Tls12(m) => {
            c.u.tls12.operation = m.operation as u32;
            c.u.tls12.prf_hash = m.prf_hash as u32;
            if let Some(r) = &m.random_info {
                c.u.tls12.has_random_info = 1;
                c.u.tls12.random_info = agc_tls12_random_info {
                    client_random_length: r.client_random_length,
                    server_random_length: r.server_random_length,
                };
            }
            if let Some(k) = &m.key_material {
                c.u.tls12.has_key_material = 1;
                c.u.tls12.key_material = agc_tls12_key_material_params {
                    mac_size_bits: k.mac_size_bits,
                    key_size_bits: k.key_size_bits,
                    iv_size_bits: k.iv_size_bits,
                };
            }
            agc_algorithm_kind_AGC_ALGORITHM_TLS12
        }
        Algorithm::Kmac(m) => {
            c.u.kmac.variant = m.variant;
            c.u.kmac.output_bits = m.output_bits;
            c.u.kmac.customization = p.bytes(&m.customization);
            agc_algorithm_kind_AGC_ALGORITHM_KMAC
        }
        Algorithm::Gost3411(m) => {
            c.u.gost3411.initial_value = p.bytes(&m.initial_value);
            agc_algorithm_kind_AGC_ALGORITHM_GOST3411
        }
        // agc_poly1305_params has no fields (only `reserved`), although the
        // pinned proto's Poly1305Params has five: they cannot be represented
        // (DEVIATIONS C8). No catalog template uses it.
        Algorithm::Poly1305(_) => {
            c.u.poly1305.reserved = 0;
            agc_algorithm_kind_AGC_ALGORITHM_POLY1305
        }
        Algorithm::Custom(m) => {
            let mut x = agc_custom_algorithm {
                vendor: p.str(&m.vendor),
                name: p.str(&m.name),
                key_type: m.key_type as u32,
                key_size_bits: m.key_size_bits,
                params_kind: agc_custom_algorithm_params_kind_AGC_CUSTOM_ALGORITHM_PARAMS_NONE,
                generic_params_json: std::ptr::null(),
                typed_params_type_url: std::ptr::null(),
                typed_params_value: agc_slice { data: std::ptr::null(), len: 0 },
            };
            match &m.params {
                None => {}
                Some(api::custom_algorithm::Params::GenericParams(s)) => {
                    x.params_kind = agc_custom_algorithm_params_kind_AGC_CUSTOM_ALGORITHM_PARAMS_GENERIC;
                    // google.protobuf.Struct as its canonical JSON (agc_algorithm_params.h).
                    let json = serde_json::to_string(s).expect("a Struct always serializes");
                    x.generic_params_json = p.str(&json);
                }
                Some(api::custom_algorithm::Params::TypedParams(any)) => {
                    x.params_kind = agc_custom_algorithm_params_kind_AGC_CUSTOM_ALGORITHM_PARAMS_TYPED;
                    x.typed_params_type_url = p.str(&any.type_url);
                    x.typed_params_value = p.bytes(&any.value);
                }
            }
            c.u.custom = x;
            agc_algorithm_kind_AGC_ALGORITHM_CUSTOM
        }
        Algorithm::Gost28147(m) => {
            c.u.gost28147.mode = m.mode as u32;
            c.u.gost28147.iv_size_bits = m.iv_size_bits;
            c.u.gost28147.sbox_oid = p.str(&m.sbox_oid);
            agc_algorithm_kind_AGC_ALGORITHM_GOST28147
        }
        Algorithm::Hybrid(m) => {
            assert!(depth < MAX_ALGORITHM_DEPTH, "catalog algorithms nest deeper than {MAX_ALGORITHM_DEPTH}");
            // Each component's algorithm is its own record in storage, so
            // the array of components is reserved first and filled after.
            let slot = p.reserve_array::<agc_hybrid_component>(m.components.len());
            let components: Vec<agc_hybrid_component> = m
                .components
                .iter()
                .map(|h| {
                    let inner = h.algorithm.as_ref().map(|a| c_algorithm_details(a, p, depth + 1));
                    let at = p.reserve_array::<agc_algorithm_details>(usize::from(inner.is_some()));
                    if let Some(inner) = inner {
                        p.fill_array(at, &[inner]);
                    }
                    agc_hybrid_component { algorithm: at.cast_const(), label: p.str(&h.label), order: h.order }
                })
                .collect();
            p.fill_array(slot, &components);
            c.u.hybrid.combiner_strategy = m.combiner_strategy as u32;
            c.u.hybrid.components = slot.cast_const();
            c.u.hybrid.components_count = components.len();
            c.u.hybrid.total_key_size_bits = m.total_key_size_bits;
            agc_algorithm_kind_AGC_ALGORITHM_HYBRID
        }
        // Every other arm is generated; build.rs checks the two lists cover
        // the oneof.
        _ => unreachable!("fill_regular_arm covers every other arm"),
    }
}

fn c_guarantees(g: &api::SecurityGuarantees, p: &mut Packer) -> agc_security_guarantees {
    let f = g.formal.unwrap_or_default();
    let pr = g.practical.unwrap_or_default();
    let b = g.bounds.clone().unwrap_or_default();
    agc_security_guarantees {
        formal: agc_formal_security_notions {
            ind_cpa: c_tribool(f.ind_cpa),
            ind_cca1: c_tribool(f.ind_cca1),
            ind_cca2: c_tribool(f.ind_cca2),
            nm_cpa: c_tribool(f.nm_cpa),
            int_ctxt: c_tribool(f.int_ctxt),
            int_ptxt: c_tribool(f.int_ptxt),
            euf_cma: c_tribool(f.euf_cma),
            suf_cma: c_tribool(f.suf_cma),
            prf: c_tribool(f.prf),
            preimage_resistant: c_tribool(f.preimage_resistant),
            second_preimage_resistant: c_tribool(f.second_preimage_resistant),
            collision_resistant: c_tribool(f.collision_resistant),
            ow_cca: c_tribool(f.ow_cca),
            ind_cca_kem: c_tribool(f.ind_cca_kem),
        },
        practical: agc_practical_security_outcomes {
            confidentiality: i32::from(pr.confidentiality),
            integrity: i32::from(pr.integrity),
            authenticity: i32::from(pr.authenticity),
            non_repudiation: i32::from(pr.non_repudiation),
        },
        bounds: agc_operational_bounds {
            authentication_strength_bits: b.authentication_strength_bits,
            max_messages_per_key: b.max_messages_per_key,
            max_plaintext_bytes_per_key: b.max_plaintext_bytes_per_key,
            attack_success_probability: p.str(&b.attack_success_probability),
        },
        additional_properties: p.kv_list(g.additional_properties.iter()),
    }
}

fn c_cyclonedx(x: &api::CycloneDxAlgorithmProperties, p: &mut Packer) -> agc_cyclonedx_algorithm_properties {
    let (crypto_functions, crypto_functions_count) = strs(p, &x.crypto_functions);
    let (certification_level, certification_level_count) = strs(p, &x.certification_level);
    agc_cyclonedx_algorithm_properties {
        name: p.str(&x.name),
        primitive: p.str(&x.primitive),
        algorithm_family: p.str(&x.algorithm_family),
        parameter_set_identifier: p.str(&x.parameter_set_identifier),
        elliptic_curve: p.str(&x.elliptic_curve),
        mode: p.str(&x.mode),
        padding: p.str(&x.padding),
        crypto_functions,
        crypto_functions_count,
        classical_security_level: x.classical_security_level,
        nist_quantum_security_level: x.nist_quantum_security_level,
        certification_level,
        certification_level_count,
        execution_environment: p.str(&x.execution_environment),
        implementation_platform: p.str(&x.implementation_platform),
        oid: p.str(&x.oid),
    }
}

/// A scope specification from the catalog. Templates are parsed when the
/// catalog loads (G5), so a scope that does not parse is a bug here.
fn catalog_scope(s: &api::ScopeSpecification) -> ScopeSpecification {
    ScopeSpecification::from_proto(s).expect("catalog scopes are validated when the catalog loads")
}

fn operations(p: &mut Packer, ops: &[i32]) -> (*const agc_crypto_operation, usize) {
    let ops: Vec<agc_crypto_operation> = ops.iter().map(|&o| o as u32).collect();
    (p.array(&ops), ops.len())
}

/// The C record of a catalog template, its variable-length data in storage.
pub fn c_template_info(t: &api::TemplateInfo, p: &mut Packer) -> agc_template_info {
    let caps_slot = p.reserve_array::<agc_scoped_capabilities>(t.scoped_capabilities.len());
    let caps: Vec<agc_scoped_capabilities> = t
        .scoped_capabilities
        .iter()
        .map(|sc| {
            let (operations, operations_count) = operations(p, &sc.operations);
            let mut c = agc_scoped_capabilities {
                scope: c_scope_spec(&catalog_scope(sc.scope.as_ref().expect("catalog scopes are present")), p),
                operations,
                operations_count,
                has_security_guarantees: 0,
                // "No claim": every tribool UNSET, every count 0.
                security_guarantees: c_guarantees(&api::SecurityGuarantees::default(), p),
            };
            if let Some(g) = &sc.security_guarantees {
                c.has_security_guarantees = 1;
                c.security_guarantees = c_guarantees(g, p);
            }
            c
        })
        .collect();
    p.fill_array(caps_slot, &caps);
    let (standards, standards_count) = strs(p, &t.standards);

    let mut c: agc_template_info = zeroed();
    c.struct_size = size_of::<agc_template_info>();
    c.template_id = p.str(&t.template_id);
    c.display_name = p.str(&t.display_name);
    c.description = p.str(&t.description);
    c.scoped_capabilities = caps_slot.cast_const();
    c.scoped_capabilities_count = caps.len();
    c.algorithm = c_algorithm_details(t.algorithm.as_ref().expect("catalog templates have an algorithm"), p, 0);
    c.status = t.status as u32;
    c.deprecation_notice = p.str(&t.deprecation_notice);
    c.standards = standards;
    c.standards_count = standards_count;
    if let Some(x) = &t.cyclonedx {
        c.has_cyclonedx = 1;
        c.cyclonedx = c_cyclonedx(x, p);
    }
    if let Some(g) = &t.security_guarantees {
        c.has_security_guarantees = 1;
        c.security_guarantees = c_guarantees(g, p);
    }
    c
}


/// The C record of a scope, its variable-length data in storage. Go sets no
/// description or use cases (ListScopes), so they are "" and empty.
pub fn c_scope_info(s: &ScopeView, p: &mut Packer) -> agc_scope_info {
    let ops: Vec<agc_crypto_operation> = s.supported_operations.iter().map(|&o| o as u32).collect();
    agc_scope_info {
        specification: c_scope_spec(&ScopeSpecification::any_of(s.scope), p),
        name: p.str(s.name),
        description: p.str(""),
        typical_use_cases: std::ptr::null_mut(),
        typical_use_cases_count: 0,
        supported_operations: p.array(&ops),
        supported_operations_count: ops.len(),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;
    use crate::adapters::storage::InMemoryTemplateRegistry;
    use crate::domain::template::TemplateRegistry;
    use crate::ffi::translation::pack_exact;

    fn s(p: *const c_char) -> &'static str {
        // SAFETY: only pointers this module wrote into live test storage.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap()
    }

    /// The parts of an algorithm that survive the trip to C, read back.
    fn check_algorithm(c: &agc_algorithm_details, a: &api::AlgorithmDetails) {
        assert_eq!(s(c.oid), a.oid);
        assert_eq!(c.primitive, a.primitive as u32);
        // SAFETY: each arm is read only under the kind that names it.
        unsafe {
            match a.algorithm.as_ref().unwrap() {
                Algorithm::AesGcm(m) => assert_eq!(
                    (c.params.u.aes_gcm.key_size_bits, c.params.u.aes_gcm.iv_size_bits, c.params.u.aes_gcm.tag_size_bits),
                    (m.key_size_bits, m.iv_size_bits, m.tag_size_bits)
                ),
                Algorithm::Ecdsa(m) => assert_eq!(
                    (c.params.u.ecdsa.curve, c.params.u.ecdsa.hash, c.params.u.ecdsa.signature_format, c.params.u.ecdsa.deterministic),
                    (m.curve as u32, m.hash as u32, m.signature_format as u32, i32::from(m.deterministic))
                ),
                Algorithm::RsaPss(m) => {
                    assert_eq!((c.params.u.rsa_pss.key_size_bits, c.params.u.rsa_pss.hash), (m.key_size_bits, m.hash as u32))
                }
                Algorithm::MlDsa(m) => assert_eq!(c.params.u.ml_dsa.parameter_set, m.parameter_set as u32),
                Algorithm::Ed448(m) => {
                    let ctx = c.params.u.ed448.context;
                    assert_eq!(ctx.len, m.context.len());
                }
                Algorithm::Kmac(m) => {
                    assert_eq!((c.params.u.kmac.variant, c.params.u.kmac.output_bits), (m.variant, m.output_bits));
                    let cust = c.params.u.kmac.customization;
                    let got = if cust.len == 0 { &[][..] } else { std::slice::from_raw_parts(cust.data, cust.len) };
                    assert_eq!(got, &m.customization[..]);
                }
                Algorithm::Hybrid(m) => {
                    let h = c.params.u.hybrid;
                    assert_eq!((h.combiner_strategy, h.components_count), (m.combiner_strategy as u32, m.components.len()));
                    for (i, comp) in m.components.iter().enumerate() {
                        let cc = &*h.components.add(i);
                        assert_eq!((s(cc.label), cc.order), (comp.label.as_str(), comp.order));
                        check_algorithm(&*cc.algorithm, comp.algorithm.as_ref().unwrap());
                    }
                }
                _ => {}
            }
        }
    }

    /// Every catalog template, in exactly measured storage: the generated and
    /// hand-written arms, kinds and every pointer checked back.
    #[test]
    fn every_catalog_template_translates() {
        let reg = InMemoryTemplateRegistry::standard();
        let mut kinds = std::collections::BTreeSet::new();
        for t in reg.list() {
            let info = t.info();
            let mut buf = vec![0u64; 4096];
            let region = agc_buf { data: buf.as_mut_ptr().cast(), cap: buf.len() * 8 };
            let mut used = 0;
            let c = pack_exact(region, &mut used, |p| c_template_info(info, p)).unwrap();
            assert_eq!(s(c.template_id), info.template_id);
            assert_eq!(s(c.display_name), info.display_name);
            assert_eq!(c.status, info.status as u32);
            assert_eq!((c.standards_count, c.scoped_capabilities_count), (info.standards.len(), info.scoped_capabilities.len()));
            for (i, std) in info.standards.iter().enumerate() {
                // SAFETY: standards holds standards_count pointers in buf.
                assert_eq!(s(unsafe { *c.standards.add(i) }), std);
            }
            for (i, sc) in info.scoped_capabilities.iter().enumerate() {
                // SAFETY: scoped_capabilities holds scoped_capabilities_count entries in buf.
                let cc = unsafe { &*c.scoped_capabilities.add(i) };
                // SAFETY: operations holds operations_count entries in buf.
                let ops = unsafe { std::slice::from_raw_parts(cc.operations, cc.operations_count) };
                assert_eq!(ops.iter().map(|&o| o as i32).collect::<Vec<_>>(), sc.operations);
                assert_eq!(cc.has_security_guarantees, i32::from(sc.security_guarantees.is_some()));
            }
            check_algorithm(&c.algorithm, info.algorithm.as_ref().unwrap());
            kinds.insert(c.algorithm.params.kind);
            assert_ne!(c.algorithm.params.kind, agc_algorithm_kind_AGC_ALGORITHM_NONE);
        }
        assert_eq!(kinds.len(), 21, "the catalog's 21 algorithm kinds");
    }

    /// Arms the catalog does not use: each irregular one, and two generated ones,
    /// with non-zero values, so that a field copied into the wrong place shows.
    #[test]
    fn arms_outside_the_catalog_translate() {
        use api::algorithm_details::Algorithm as A;
        let cases: Vec<(A, agc_algorithm_kind)> = vec![
            (
                A::Gost3410(api::Gost3410Params {
                    version: 1,
                    key_size_bits: 512,
                    parameter_set_oid: "1.2.643.7.1.2.1.2.1".into(),
                    digest_param_set_oid: "".into(),
                }),
                agc_algorithm_kind_AGC_ALGORITHM_GOST3410,
            ),
            (
                A::Tls12(api::Tls12Params {
                    operation: 1,
                    prf_hash: api::HashAlgorithm::Sha384 as i32,
                    random_info: Some(api::tls12_params::RandomInfo { client_random_length: 32, server_random_length: 31 }),
                    key_material: None,
                }),
                agc_algorithm_kind_AGC_ALGORITHM_TLS12,
            ),
            (A::Poly1305(Default::default()), agc_algorithm_kind_AGC_ALGORITHM_POLY1305),
            (
                A::AesCcm(api::AesCcmParams { key_size_bits: 256, nonce_size_bits: 104, tag_size_bits: 112 }),
                agc_algorithm_kind_AGC_ALGORITHM_AES_CCM,
            ),
        ];
        for (alg, kind) in cases {
            let a = api::AlgorithmDetails { oid: "x".into(), primitive: 0, algorithm: Some(alg) };
            let mut buf = vec![0u64; 256];
            let region = agc_buf { data: buf.as_mut_ptr().cast(), cap: buf.len() * 8 };
            let mut used = 0;
            let c = pack_exact(region, &mut used, |p| c_algorithm_details(&a, p, 0)).unwrap();
            assert_eq!(c.params.kind, kind);
            // SAFETY: each arm is read under its kind.
            unsafe {
                match kind {
                    agc_algorithm_kind_AGC_ALGORITHM_GOST3410 => {
                        assert_eq!((c.params.u.gost3410.key_size_bits, s(c.params.u.gost3410.parameter_set_oid)), (512, "1.2.643.7.1.2.1.2.1"));
                    }
                    agc_algorithm_kind_AGC_ALGORITHM_TLS12 => {
                        let t = c.params.u.tls12;
                        assert_eq!((t.prf_hash, t.has_random_info, t.random_info.server_random_length, t.has_key_material), (2, 1, 31, 0));
                    }
                    agc_algorithm_kind_AGC_ALGORITHM_AES_CCM => {
                        let m = c.params.u.aes_ccm;
                        assert_eq!((m.key_size_bits, m.nonce_size_bits, m.tag_size_bits), (256, 104, 112));
                    }
                    _ => {}
                }
            }
        }
    }
}
