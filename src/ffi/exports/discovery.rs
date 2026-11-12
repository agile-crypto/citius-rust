//! agc_discovery.h (AlgorithmDiscoveryService) and the read half of
//! agc_provider.h (ProviderService), as Go's handlers serve them. The
//! application service `Discovery` does the work; this layer translates.
//!
//! Iterators hold a snapshot taken when the listing starts, so they do not
//! depend on their context (as agc_list_keys). `page_size` is accepted and
//! has no effect: the iterator yields every item, and Go's paging has no
//! maximum page size that a value here could exceed.

use std::ffi::c_char;

use crate::app::{InstanceView, ProviderView, TemplateFilter};
use crate::bindings::*;
use crate::ffi::error::FfiError;
use crate::ffi::exports::core::{clear_handle, context};
use crate::ffi::guard::{guard, guard_value};
use crate::ffi::translation::{
    Packer, c_matched_provider, c_provider_info, c_provider_instance, c_scope_info, c_template_info, optional_str,
    pack, pack_exact, provider_requirements, required_str, scope_spec,
};
use crate::ffi::versioned;
use crate::proto::api;

/// A snapshot to iterate over.
struct Iter<T> {
    items: Vec<T>,
    next: usize,
}

/// One step of an iterator over `T`: fill the caller's response with the
/// next item, advancing only on success, so that on BUFFER_TOO_SMALL the
/// caller can grow the storage and retry the same item (agc_discovery.h).
///
/// # Safety
/// `it` is NULL or an iterator of `Iter<T>` from this module, not freed and
/// used by one thread at a time; `out` is NULL or the caller's struct with
/// struct_size accessible bytes.
unsafe fn iter_next<T, R: versioned::CStruct>(
    it: *mut Iter<T>,
    out: *mut R,
    fill: impl FnOnce(&T, &mut R) -> Result<(), FfiError>,
) -> agc_rc {
    guard(|| {
        // SAFETY: forwarded from this function's contract.
        let it = unsafe { it.as_mut() }.ok_or_else(|| FfiError::invalid("it must not be NULL"))?;
        // SAFETY: forwarded from this function's contract.
        let mut resp = unsafe { versioned::read(out, "out") }?;
        let item = it.items.get(it.next).ok_or(FfiError::IteratorExhausted)?;
        let result = fill(item, &mut resp);
        // SAFETY: out passed versioned::read above.
        unsafe { versioned::write_back(out, &resp) };
        if result.is_ok() {
            it.next += 1;
        }
        result
    })
}

/// Frees an iterator from this module.
///
/// # Safety
/// `it` is NULL or came from `start` and is freed once.
unsafe fn iter_free<T>(it: *mut Iter<T>) {
    if !it.is_null() {
        // SAFETY: forwarded from this function's contract.
        guard_value((), || drop(unsafe { Box::from_raw(it) }))
    }
}

/// Hands a new iterator to the caller.
///
/// # Safety
/// `out` is non-NULL and points to the caller's handle variable.
unsafe fn start<T, H>(items: Vec<T>, out: *mut *mut H) {
    let it = Box::new(Iter { items, next: 0 });
    // SAFETY: forwarded from this function's contract.
    unsafe { out.write(Box::into_raw(it).cast()) };
}

/// Clears the caller's handle (agc_core.h convention 6), then requires one.
fn required_out<T>(out: *mut *mut T, what: &str) -> Result<(), FfiError> {
    // SAFETY: out is NULL or the caller's handle variable (the exports' contract).
    unsafe { clear_handle(out) };
    if out.is_null() {
        return Err(FfiError::invalid(format!("{what} must not be NULL")));
    }
    Ok(())
}

fn fill_template(t: &api::TemplateInfo, resp: &mut agc_template_info_response) -> Result<(), FfiError> {
    resp.template_info = pack(resp.storage, &mut resp.storage_used, |p| c_template_info(t, p))?;
    Ok(())
}

fn fill_provider(v: &ProviderView, resp: &mut agc_provider_info_response) -> Result<(), FfiError> {
    resp.provider = pack(resp.storage, &mut resp.storage_used, |p| c_provider_info(v, p))?;
    Ok(())
}

fn fill_instance(v: &InstanceView, resp: &mut agc_provider_instance_response) -> Result<(), FfiError> {
    resp.instance = pack(resp.storage, &mut resp.storage_used, |p| c_provider_instance(v, p))?;
    Ok(())
}

/// The array half of the two-call rule for caller-allocated arrays
/// (agc_list_scopes_response, agc_match_providers_response): `count` is
/// always set; if the array is NULL or too small, `storage_used` is set to
/// what the entries need and nothing else is written.
fn check_array<T>(array: *mut T, cap: usize, n: usize, count: &mut usize, storage_used: &mut usize, size: usize) -> Result<(), FfiError> {
    *count = n;
    if n > 0 && (array.is_null() || cap < n) {
        *storage_used = size;
        return Err(FfiError::BufferTooSmall { needed: n });
    }
    Ok(())
}

/// Writes `entries` into the caller's array (whose capacity `check_array`
/// accepted).
///
/// # Safety
/// `array` has room for `entries.len()` elements (or `entries` is empty).
unsafe fn write_entries<T: Copy>(array: *mut T, entries: &[T]) {
    if !entries.is_empty() {
        // SAFETY: forwarded from this function's contract; the entries are a
        // separate Rust allocation.
        unsafe { std::ptr::copy_nonoverlapping(entries.as_ptr(), array, entries.len()) };
    }
}

// --- agc_discovery.h --------------------------------------------------------

type TemplateIter = Iter<api::TemplateInfo>;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_list_templates(
    ctx: *mut agc_ctx,
    p: *const agc_list_templates_params,
    out_iter: *mut *mut agc_template_iter,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        required_out(out_iter, "out_iter")?;
        // SAFETY: p is NULL or the caller's struct with struct_size readable bytes.
        let r = unsafe { versioned::read(p, "p") }?;
        // SAFETY: scope_spec is NULL or a valid agc_scope_spec (agc_discovery_types.h).
        let scope_spec = match unsafe { r.scope_spec.as_ref() } {
            None => None,
            // SAFETY: as above, including its additional_properties.
            Some(s) => Some(unsafe { scope_spec(s) }?),
        };
        let statuses = if r.allowed_statuses_count == 0 {
            &[][..]
        } else if r.allowed_statuses.is_null() {
            return Err(FfiError::invalid("allowed_statuses is NULL but allowed_statuses_count is not 0"));
        } else {
            // SAFETY: non-null and valid for allowed_statuses_count entries (header contract).
            unsafe { std::slice::from_raw_parts(r.allowed_statuses, r.allowed_statuses_count) }
        };
        let allowed_statuses = statuses
            .iter()
            .map(|&s| {
                i32::try_from(s)
                    .ok()
                    .and_then(|s| api::TemplateStatus::try_from(s).ok())
                    .ok_or_else(|| FfiError::invalid(format!("allowed_statuses: {s} is not a template status")))
            })
            .collect::<Result<_, _>>()?;
        let standards = r.required_standards;
        if standards.count != 0 && standards.items.is_null() {
            return Err(FfiError::invalid("required_standards.items is NULL but count is not 0"));
        }
        let required_standards = (0..standards.count)
            .map(|i| {
                // SAFETY: items is valid for count strings, each NULL or a C string (header contract).
                unsafe { required_str(*standards.items.add(i), "required_standards") }.map(str::to_owned)
            })
            .collect::<Result<_, _>>()?;
        let items = ctx.discovery.list_templates(&TemplateFilter { scope_spec, allowed_statuses, required_standards });
        // SAFETY: out_iter is non-NULL (checked) and points to the caller's variable.
        unsafe { start::<_, agc_template_iter>(items, out_iter) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_template_iter_next(it: *mut agc_template_iter, out: *mut agc_template_info_response) -> agc_rc {
    // SAFETY: it is NULL or from agc_list_templates (agc_discovery.h); out per the header.
    unsafe { iter_next(it.cast::<TemplateIter>(), out, fill_template) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_template_iter_free(it: *mut agc_template_iter) {
    // SAFETY: it is NULL or from agc_list_templates, freed once.
    unsafe { iter_free(it.cast::<TemplateIter>()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_get_template(
    ctx: *mut agc_ctx,
    template_id: *const c_char,
    resp: *mut agc_template_info_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: template_id is NULL or a C string (agc_discovery.h contract).
        let id = unsafe { optional_str(template_id, "template_id") }?.unwrap_or_default();
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let t = ctx.discovery.get_template(id)?;
        let result = fill_template(&t, &mut out);
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_list_scopes(ctx: *mut agc_ctx, resp: *mut agc_list_scopes_response) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let scopes = ctx.discovery.list_scopes();
        let lay_out = |p: &mut Packer| scopes.iter().map(|s| c_scope_info(s, p)).collect::<Vec<_>>();
        let result = (|| {
            let mut m = Packer::measuring_at(out.storage.data);
            lay_out(&mut m);
            check_array(out.scopes, out.scopes_cap, scopes.len(), &mut out.scopes_count, &mut out.storage_used, m.used())?;
            let entries = pack_exact(out.storage, &mut out.storage_used, lay_out)?;
            // SAFETY: check_array accepted the array's capacity for the entries.
            unsafe { write_entries(out.scopes, &entries) };
            Ok(())
        })();
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

// --- agc_provider.h ---------------------------------------------------------

type ProviderIter = Iter<ProviderView>;
type InstanceIter = Iter<InstanceView>;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_list_providers(
    ctx: *mut agc_ctx,
    req: *const agc_list_providers_request,
    out_iter: *mut *mut agc_provider_iter,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        required_out(out_iter, "out_iter")?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let r = unsafe { versioned::read(req, "req") }?;
        // SAFETY: template_id is NULL or a C string (agc_provider_types.h).
        let template = unsafe { optional_str(r.template_id, "template_id") }?.filter(|t| !t.is_empty());
        // SAFETY: requirements is NULL or a versioned struct (agc_provider_types.h).
        let required = unsafe { provider_requirements(r.requirements) }?;
        let items = ctx.discovery.list_providers(template, &required);
        // SAFETY: out_iter is non-NULL (checked) and points to the caller's variable.
        unsafe { start::<_, agc_provider_iter>(items, out_iter) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_provider_iter_next(it: *mut agc_provider_iter, out: *mut agc_provider_info_response) -> agc_rc {
    // SAFETY: it is NULL or from agc_list_providers (agc_provider.h); out per the header.
    unsafe { iter_next(it.cast::<ProviderIter>(), out, fill_provider) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_provider_iter_free(it: *mut agc_provider_iter) {
    // SAFETY: it is NULL or from agc_list_providers, freed once.
    unsafe { iter_free(it.cast::<ProviderIter>()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_get_provider(
    ctx: *mut agc_ctx,
    provider_id: *const c_char,
    resp: *mut agc_provider_info_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: provider_id is NULL or a C string (agc_provider.h contract).
        let id = unsafe { optional_str(provider_id, "provider_id") }?.unwrap_or_default();
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let v = ctx.discovery.get_provider(id)?;
        let result = fill_provider(&v, &mut out);
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_list_provider_instances(
    ctx: *mut agc_ctx,
    req: *const agc_list_provider_instances_request,
    out_iter: *mut *mut agc_provider_instance_iter,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        required_out(out_iter, "out_iter")?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let r = unsafe { versioned::read(req, "req") }?;
        // SAFETY: provider_id is NULL or a C string (agc_provider_types.h).
        let provider = unsafe { optional_str(r.provider_id, "provider_id") }?.filter(|p| !p.is_empty());
        // SAFETY: requirements is NULL or a versioned struct (agc_provider_types.h).
        let required = unsafe { provider_requirements(r.requirements) }?;
        // Every instance is enabled, so enabled_only changes nothing (as Go).
        let items = ctx.discovery.list_instances(provider, &required);
        // SAFETY: out_iter is non-NULL (checked) and points to the caller's variable.
        unsafe { start::<_, agc_provider_instance_iter>(items, out_iter) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_provider_instance_iter_next(
    it: *mut agc_provider_instance_iter,
    out: *mut agc_provider_instance_response,
) -> agc_rc {
    // SAFETY: it is NULL or from agc_list_provider_instances; out per the header.
    unsafe { iter_next(it.cast::<InstanceIter>(), out, fill_instance) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_provider_instance_iter_free(it: *mut agc_provider_instance_iter) {
    // SAFETY: it is NULL or from agc_list_provider_instances, freed once.
    unsafe { iter_free(it.cast::<InstanceIter>()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_get_provider_instance(
    ctx: *mut agc_ctx,
    instance_id: *const c_char,
    resp: *mut agc_provider_instance_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: instance_id is NULL or a C string (agc_provider.h contract).
        let id = unsafe { optional_str(instance_id, "instance_id") }?.unwrap_or_default();
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let v = ctx.discovery.get_instance(id)?;
        let result = fill_instance(&v, &mut out);
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_match_providers(
    ctx: *mut agc_ctx,
    req: *const agc_match_providers_request,
    resp: *mut agc_match_providers_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let r = unsafe { versioned::read(req, "req") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        // SAFETY: template_id is NULL or a C string (agc_provider_types.h).
        let template = unsafe { optional_str(r.template_id, "template_id") }?.unwrap_or_default();
        // SAFETY: requirements is NULL or a versioned struct (agc_provider_types.h).
        let required = unsafe { provider_requirements(r.requirements) }?;
        // No instance is disabled, so enabled_only changes nothing (as Go).
        let matches = ctx.discovery.match_providers(template, &required)?;
        let lay_out = |p: &mut Packer| matches.iter().map(|m| c_matched_provider(m, p)).collect::<Vec<_>>();
        let result = (|| {
            let mut m = Packer::measuring_at(out.storage.data);
            lay_out(&mut m);
            check_array(out.matches, out.matches_cap, matches.len(), &mut out.matches_count, &mut out.storage_used, m.used())?;
            let entries = pack_exact(out.storage, &mut out.storage_used, lay_out)?;
            // SAFETY: check_array accepted the array's capacity for the entries.
            unsafe { write_entries(out.matches, &entries) };
            Ok(())
        })();
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}
