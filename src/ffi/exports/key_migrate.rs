//! agc_key.h — MigrateKey and ValidateKeyOperation.

use std::ptr;

use crate::app::{MigrateSpec, MigrateTarget, MigrationResult, MigrationValidation, StrategyAssessment, TransformSpec};
use crate::bindings::*;
use crate::ffi::error::FfiError;
use crate::ffi::exports::core::context;
use crate::ffi::guard::guard;
use crate::ffi::translation::{Packer, c_impl_props, c_key_info, optional_str, pack, required_str, scope_spec, strs};
use crate::ffi::versioned;
use crate::proto::api;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_migrate_key(
    ctx: *mut agc_ctx,
    params: *const agc_migrate_key_params,
    resp: *mut agc_migrate_key_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: params is NULL or the caller's struct with struct_size readable bytes.
        let p = unsafe { versioned::read(params, "params") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        // SAFETY: the pointers in params are NULL or valid (agc_key.h contract).
        let spec = unsafe { migrate_spec(&p) }?;

        // The records the caller asked for are size-checked before the key
        // moves (agc_key.h): on BUFFER_TOO_SMALL no key has been touched.
        let storage = out.storage;
        let (want_info, want_report) = (out.want_key_info != 0, out.want_report != 0);
        let wants_props = !out.report.target_implementation_properties.is_null();
        let mut needed = None;
        let migrated = ctx.keys.migrate_key_admitting(spec, |r: &MigrationResult| {
            let mut m = Packer::measuring();
            layout_migration(r, want_info, want_report, wants_props, &mut m);
            let n = m.used();
            if n > 0 && (storage.data.is_null() || storage.cap < n) {
                needed = Some(n);
                return Err(FfiError::BufferTooSmall { needed: n });
            }
            Ok(())
        });
        let result = match migrated {
            Ok(r) => fill_migrate_response(&mut out, &r),
            Err(e) => {
                if let Some(n) = needed {
                    out.storage_used = n;
                }
                Err(e)
            }
        };
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

/// # Safety
/// The pointers in `p` are NULL or valid for the duration of the call.
unsafe fn migrate_spec(p: &agc_migrate_key_params) -> Result<MigrateSpec, FfiError> {
    // SAFETY: forwarded from this function's contract.
    let key_name = unsafe { required_str(p.key_name, "key_name") }?.to_owned();
    // A migration keeps the key's algorithm (as in Go): changing it on the
    // way is not offered, and refused rather than ignored.
    // SAFETY: as above.
    if !p.scope_spec.is_null() || unsafe { optional_str(p.template_id, "template_id") }?.is_some() {
        return Err(FfiError::NotImplemented("changing the algorithm during a migration (use agc_transform_key)"));
    }
    let target = match p.target.kind {
        agc_migrate_target_kind_AGC_MIGRATE_TARGET_INSTANCE => {
            // SAFETY: kind selects instance_id, NULL or a valid C string.
            MigrateTarget::Instance(unsafe { required_str(p.target.u.instance_id, "target.u.instance_id") }?.to_owned())
        }
        agc_migrate_target_kind_AGC_MIGRATE_TARGET_PROVIDER => {
            // SAFETY: kind selects the provider member.
            let t = unsafe { &p.target.u.provider };
            if t.configuration.count != 0 {
                return Err(FfiError::NotImplemented("target.u.provider.configuration"));
            }
            // SAFETY: provider_id is NULL or a valid C string.
            MigrateTarget::ProviderKind(unsafe { required_str(t.provider_id, "target.u.provider.provider_id") }?.to_owned())
        }
        _ => return Err(FfiError::invalid("target.kind must be INSTANCE or PROVIDER")),
    };
    Ok(MigrateSpec { key_name, target, strategy: strategy(p.strategy, "strategy")? })
}

fn strategy(v: agc_migration_strategy, what: &str) -> Result<api::MigrationStrategy, FfiError> {
    i32::try_from(v)
        .ok()
        .and_then(|v| api::MigrationStrategy::try_from(v).ok())
        .ok_or_else(|| FfiError::invalid(format!("{what} {v} is not a known strategy")))
}

/// Lays out the records a migration returns: the key's record and the
/// report, as requested. Returns them, and the implementation properties to
/// write through the caller's pointer.
fn layout_migration(
    r: &MigrationResult,
    want_info: bool,
    want_report: bool,
    wants_props: bool,
    p: &mut Packer,
) -> (Option<agc_key_info>, Option<agc_migration_report>, Option<agc_impl_props>) {
    let info = want_info.then(|| c_key_info(&r.key, p));
    let props = (want_report && wants_props).then(|| c_impl_props(&r.target_implementation, p));
    let report = want_report.then(|| {
        let archived = r.strategy == api::MigrationStrategy::RekeyAndArchive;
        agc_migration_report {
            struct_size: size_of::<agc_migration_report>(),
            strategy_used: r.strategy as u32,
            key_bytes_preserved: i32::from(r.key_bytes_preserved),
            source_provider_id: p.str(&r.source_kind),
            source_instance_id: p.str(&r.source_instance),
            target_provider_id: p.str(&r.target_kind),
            target_instance_id: p.str(&r.target_instance),
            has_target_implementation_properties: i32::from(props.is_some()),
            target_implementation_properties: ptr::null_mut(), // the caller's pointer is kept, see below
            wrapping_key_name: p.str(""),
            // REKEY_AND_ARCHIVE keeps the previous version of this same key on
            // its provider: it is addressed by the key's name (Go).
            has_archived_key: i32::from(archived),
            archived_key_name: if archived { p.str(&r.key.name) } else { ptr::null() },
            archived_provider_id: if archived { p.str(&r.source_instance) } else { ptr::null() },
            // Go does not report which operations the archived version still
            // allows (its ArchivedKeyInfo leaves allowed_operations empty).
            archived_allowed_operations: ptr::null(),
            archived_allowed_operations_count: 0,
            archived_expiration: agc_timestamp { seconds: 0, nanos: 0, present: 0 },
        }
    });
    (info, report, props)
}

fn fill_migrate_response(out: &mut agc_migrate_key_response, r: &MigrationResult) -> Result<(), FfiError> {
    let (want_info, want_report) = (out.want_key_info != 0, out.want_report != 0);
    let props_out = out.report.target_implementation_properties;
    if !want_info && !want_report {
        out.storage_used = 0;
        return Ok(());
    }
    let (info, report, props) =
        pack(out.storage, &mut out.storage_used, |p| layout_migration(r, want_info, want_report, !props_out.is_null(), p))?;
    if let Some(info) = info {
        out.key_info = info;
    }
    if let Some(mut report) = report {
        report.target_implementation_properties = props_out;
        out.report = report;
    }
    if let Some(props) = props {
        // SAFETY: the caller set this pointer to its own agc_impl_props to
        // receive them (agc_key_types.h); the strings point into storage.
        unsafe { props_out.write(props) };
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_validate_key_operation(
    ctx: *mut agc_ctx,
    params: *const agc_validate_key_op_params,
    out_report: *mut agc_validate_key_op_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: params is NULL or the caller's struct with struct_size readable bytes.
        let p = unsafe { versioned::read(params, "params") }?;
        // SAFETY: out_report is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(out_report, "out_report") }?;
        // SAFETY: key_name is NULL or a valid C string (agc_key.h contract).
        let key_name = unsafe { required_str(p.key_name, "key_name") }?;

        let assessment = match p.kind {
            agc_validate_intent_kind_AGC_VALIDATE_INTENT_MIGRATE => {
                // SAFETY: kind selects the migrate member.
                let m = unsafe { &p.u.migrate };
                // SAFETY: target_id is NULL or a valid C string.
                let id = || unsafe { required_str(m.target_id, "u.migrate.target_id") }.map(str::to_owned);
                let target = match m.target_kind {
                    agc_validate_migrate_target_kind_AGC_VALIDATE_MIGRATE_TARGET_ANY => MigrateTarget::Any,
                    agc_validate_migrate_target_kind_AGC_VALIDATE_MIGRATE_TARGET_INSTANCE => MigrateTarget::Instance(id()?),
                    agc_validate_migrate_target_kind_AGC_VALIDATE_MIGRATE_TARGET_PROVIDER => {
                        MigrateTarget::ProviderKind(id()?)
                    }
                    other => return Err(FfiError::invalid(format!("u.migrate.target_kind {other} is not known"))),
                };
                let preferred = match m.preferred_strategy {
                    0 => None,
                    s => Some(strategy(s, "u.migrate.preferred_strategy")?),
                };
                ctx.keys.validate_migration(key_name, target, preferred)?
            }
            agc_validate_intent_kind_AGC_VALIDATE_INTENT_TRANSFORM => {
                // SAFETY: kind selects the transform member; its pointers are NULL or valid.
                let t = unsafe { &p.u.transform };
                // SAFETY: as above.
                let scope = match unsafe { t.scope_spec.as_ref() } {
                    None => None,
                    // SAFETY: as above, including its additional_properties.
                    Some(s) => Some(unsafe { scope_spec(s) }?),
                };
                // SAFETY: template_id is NULL or a valid C string.
                let template_id = unsafe { optional_str(t.template_id, "u.transform.template_id") }?.map(str::to_owned);
                assess_transform(ctx, key_name, scope, template_id, t.prefer_retain_bytes != 0)?
            }
            _ => return Err(FfiError::invalid("kind must be TRANSFORM or MIGRATE")),
        };

        // A read-only call: its storage requirement is exact, and nothing
        // but storage_used is written when the region is too small.
        let props_out = out.current_state.implementation_properties;
        let packed = pack(out.storage, &mut out.storage_used, |p| layout_validation(&assessment, !props_out.is_null(), p));
        let result = packed.map(|(state, options, reason, props)| {
            out.current_state = state;
            out.current_state.implementation_properties = props_out;
            out.options = options;
            out.option_count = assessment.options.len();
            out.recommended_strategy = assessment.recommended as u32;
            out.recommendation_reason = reason;
            if let Some(props) = props {
                // SAFETY: the caller set this pointer to its own agc_impl_props
                // to receive them (agc_key_types.h); strings point into storage.
                unsafe { props_out.write(props) };
            }
        });
        // SAFETY: out_report passed versioned::read above.
        unsafe { versioned::write_back(out_report, &out) };
        result
    })
}

/// Lays out a validation report: the key's state, the options and the
/// recommendation; returns them and the implementation properties to write
/// through the caller's pointer.
fn layout_validation(
    v: &MigrationValidation,
    wants_props: bool,
    p: &mut Packer,
) -> (agc_key_state, *const agc_strategy_option, *const std::ffi::c_char, Option<agc_impl_props>) {
    let props = if wants_props { v.source_implementation.as_ref().map(|i| c_impl_props(i, p)) } else { None };
    let state = agc_key_state {
        template_id: p.str(&v.template_id),
        provider_id: p.str(v.source_kind.as_deref().unwrap_or("")),
        instance_id: p.str(&v.source_instance),
        extractable: i32::from(v.extractable),
        provider_type: match v.source_kind.as_deref() {
            Some("software") => agc_provider_type_AGC_PROVIDER_TYPE_SOFTWARE,
            _ => agc_provider_type_AGC_PROVIDER_TYPE_UNSPECIFIED,
        },
        has_implementation_properties: i32::from(props.is_some()),
        implementation_properties: ptr::null_mut(), // the caller's pointer is kept
    };
    let options: Vec<agc_strategy_option> = v.options.iter().map(|o| c_option(o, p)).collect();
    let options = p.array(&options);
    let reason = p.str(&v.recommendation_reason);
    (state, options, reason, props)
}

fn c_option(o: &StrategyAssessment, p: &mut Packer) -> agc_strategy_option {
    let (security_notes, security_notes_count) = strs(p, &o.security_notes);
    agc_strategy_option {
        strategy: o.strategy as u32,
        feasible: i32::from(o.feasible),
        infeasibility_reason: p.str(&o.reason),
        security_notes,
        security_notes_count,
        // The proto defines a 1-5 scale, which nothing here can substantiate
        // (Go does not set it either): 0, "not assessed".
        complexity_level: 0,
    }
}

/// A transform pre-flight, as a report with one option.
fn assess_transform(
    ctx: &crate::ffi::context::Context,
    key_name: &str,
    scope_spec: Option<crate::domain::core::ScopeSpecification>,
    template_id: Option<String>,
    prefer_retain: bool,
) -> Result<MigrationValidation, FfiError> {
    let spec = TransformSpec { key_name: key_name.to_owned(), retain: prefer_retain, scope_spec, template_id };
    Ok(ctx.keys.validate_transform(spec)?)
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, c_char};
    use std::time::SystemTime;

    use super::*;
    use crate::app::KeyMetadata;
    use crate::domain::core::{Scope, ScopeSpecification};
    use crate::domain::key::KeyId;

    fn result() -> MigrationResult {
        MigrationResult {
            key: KeyMetadata {
                id: KeyId::new("key_1"),
                name: "k".into(),
                policy: "p".into(),
                state: api::KeyLifecycleState::Active,
                created_at: SystemTime::UNIX_EPOCH,
                updated_at: SystemTime::UNIX_EPOCH,
                version: 2,
                template_id: "chacha20-poly1305".into(),
                provider: "hsm-1".into(),
                scope_spec: ScopeSpecification::any_of(Scope::Aead(api::AeadScope::Standard)),
                extractable: false,
                public_key: None,
                implementation: api::ImplementationProperties::default(),
                origin: api::KeyOrigin::Generated,
            },
            strategy: api::MigrationStrategy::RekeyAndArchive,
            key_bytes_preserved: false,
            source_kind: "software".into(),
            source_instance: "rustcrypto".into(),
            source_version: 1,
            target_kind: "hsm".into(),
            target_instance: "hsm-1".into(),
            target_implementation: api::ImplementationProperties {
                implementation_language: "c".into(),
                constant_time: Some(true),
                ..Default::default()
            },
        }
    }

    fn s(p: *const c_char) -> &'static str {
        assert!(!p.is_null());
        // SAFETY: points into a live test buffer; the packer NUL-terminates.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap()
    }

    fn response(storage: &mut [u8], props: *mut agc_impl_props) -> agc_migrate_key_response {
        // SAFETY: integers and raw pointers only; all zeros is AGC_INIT's state.
        let mut r: agc_migrate_key_response = unsafe { std::mem::zeroed() };
        r.struct_size = size_of::<agc_migrate_key_response>();
        r.want_key_info = 1;
        r.want_report = 1;
        r.report.target_implementation_properties = props;
        r.storage = agc_buf { data: storage.as_mut_ptr(), cap: storage.len() };
        r
    }

    #[test]
    fn the_report_and_record_are_written_as_requested() {
        let mut storage = [0u8; 1024];
        // SAFETY: integers and raw pointers only.
        let mut props: agc_impl_props = unsafe { std::mem::zeroed() };
        let mut r = response(&mut storage, &mut props);
        fill_migrate_response(&mut r, &result()).unwrap();

        assert_eq!((s(r.key_info.key_name), r.key_info.version, r.key_info.extractable), ("k", 2, 0));
        let rep = &r.report;
        assert_eq!(rep.strategy_used, agc_migration_strategy_AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE);
        assert_eq!((s(rep.source_provider_id), s(rep.source_instance_id)), ("software", "rustcrypto"));
        assert_eq!((s(rep.target_provider_id), s(rep.target_instance_id)), ("hsm", "hsm-1"));
        assert_eq!((rep.has_archived_key, s(rep.archived_key_name), s(rep.archived_provider_id)), (1, "k", "rustcrypto"));
        assert!(rep.archived_allowed_operations.is_null() && rep.archived_allowed_operations_count == 0, "as in Go: not reported");
        assert_eq!(s(rep.wrapping_key_name), "");
        assert_eq!(rep.has_target_implementation_properties, 1);
        assert_eq!(rep.target_implementation_properties, &raw mut props, "the caller's pointer is kept");
        assert_eq!((s(props.implementation_language), props.constant_time), ("c", agc_tribool_AGC_TRUE));
    }

    #[test]
    fn only_what_was_asked_is_laid_out() {
        let mut storage = [0u8; 1024];
        let mut r = response(&mut storage, ptr::null_mut());
        r.want_key_info = 0;
        fill_migrate_response(&mut r, &result()).unwrap();
        assert!(r.key_info.key_name.is_null());
        assert_eq!(r.report.has_target_implementation_properties, 0);

        let mut none = response(&mut [], ptr::null_mut());
        none.want_key_info = 0;
        none.want_report = 0;
        none.storage = agc_buf { data: ptr::null_mut(), cap: 0 };
        fill_migrate_response(&mut none, &result()).unwrap();
        assert_eq!(none.storage_used, 0, "a bare migration needs no storage");
    }

    #[test]
    fn an_option_carries_its_security_notes() {
        let o = StrategyAssessment {
            strategy: api::MigrationStrategy::RekeyAndDestroy,
            feasible: false,
            reason: "no".into(),
            target_instance: None,
            security_notes: vec!["first".into(), "second".into()],
        };
        let mut storage = [0u8; 256];
        let mut used = 0;
        let c = pack(agc_buf { data: storage.as_mut_ptr(), cap: storage.len() }, &mut used, |p| c_option(&o, p)).unwrap();
        assert_eq!(c.security_notes_count, 2);
        // SAFETY: security_notes points at two string pointers in storage.
        let notes = unsafe { std::slice::from_raw_parts(c.security_notes, 2) };
        assert_eq!((s(notes[0]), s(notes[1]), s(c.infeasibility_reason)), ("first", "second", "no"));

        let none = StrategyAssessment { security_notes: Vec::new(), ..o };
        let c = pack(agc_buf { data: storage.as_mut_ptr(), cap: storage.len() }, &mut used, |p| c_option(&none, p)).unwrap();
        assert!(c.security_notes.is_null() && c.security_notes_count == 0, "empty is NULL, 0");
    }

    #[test]
    fn a_small_region_writes_only_the_size() {
        let mut storage = [0xAAu8; 16];
        let mut r = response(&mut storage, ptr::null_mut());
        assert!(matches!(fill_migrate_response(&mut r, &result()), Err(FfiError::BufferTooSmall { .. })));
        assert!(r.storage_used > 16);
        assert!(r.key_info.key_name.is_null() && r.report.source_instance_id.is_null());
        assert!(storage.iter().all(|&b| b == 0xAA));
    }
}
