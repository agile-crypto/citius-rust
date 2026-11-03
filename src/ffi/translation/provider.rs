//! Providers and instances to their C form (agc_provider_types.h), filled
//! the way Go's ProviderHandler fills the proto messages.

use std::ptr;

use super::{Packer, c_impl_props};
use crate::app::{InstanceView, Match, ProviderView};
use crate::bindings::*;

/// Go's `providerInfo` sets the id, the display name (the id again) and the
/// template support, each entry noting the instances that serve it; it sets
/// no type, description, capabilities, configuration schema or default
/// implementation, and leaves `enabled` false.
pub fn c_provider_info(v: &ProviderView, p: &mut Packer) -> agc_provider_info {
    let support = v.template_support();
    let slot = p.reserve_array::<agc_provider_template_support>(support.len());
    let entries: Vec<agc_provider_template_support> = support
        .iter()
        .map(|(template, instances)| agc_provider_template_support {
            template_id: p.str(template),
            has_implementation: 0,
            implementation: c_impl_props(&Default::default(), p),
            notes: p.str(&format!("instances: {}", instances.join(", "))),
            enabled: 0,
        })
        .collect();
    p.fill_array(slot, &entries);
    agc_provider_info {
        struct_size: size_of::<agc_provider_info>(),
        provider_id: p.str(&v.id),
        display_name: p.str(&v.id),
        description: p.str(""),
        provider_type: agc_provider_type_AGC_PROVIDER_TYPE_UNSPECIFIED,
        capabilities: agc_kv_list { items: ptr::null(), count: 0 },
        configuration_schema: ptr::null(),
        configuration_schema_count: 0,
        has_default_implementation: 0,
        default_implementation: c_impl_props(&Default::default(), p),
        template_support: slot.cast_const(),
        template_support_count: entries.len(),
    }
}

/// Go's `instanceInfo`: the instance id and display name are the backend's
/// name, the provider its kind, the implementation it reports goes in
/// `implementation_override`.
pub fn c_provider_instance(v: &InstanceView, p: &mut Packer) -> agc_provider_instance {
    agc_provider_instance {
        struct_size: size_of::<agc_provider_instance>(),
        instance_id: p.str(&v.instance_id),
        provider_id: p.str(&v.provider_id),
        display_name: p.str(&v.instance_id),
        description: p.str(""),
        configuration: agc_kv_list { items: ptr::null(), count: 0 },
        // Go leaves `enabled` unset, so every instance it reports reads as
        // disabled although every served instance is enabled (DEVIATIONS G32).
        enabled: 1,
        // Go: absent when the backend reports no properties.
        has_implementation_override: i32::from(v.implementation != Default::default()),
        implementation_override: c_impl_props(&v.implementation, p),
    }
}

pub fn c_matched_provider(m: &Match, p: &mut Packer) -> agc_matched_provider {
    agc_matched_provider {
        instance: c_provider_instance(&m.instance, p),
        has_resolved_implementation: 1,
        resolved_implementation: c_impl_props(&m.resolved_implementation, p),
        match_score: m.score,
    }
}
