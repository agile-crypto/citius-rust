use crate::bindings::*;
use std::ffi::CStr;

// TODO: Toy definitions. Replace them by correct ones later
pub struct KeyRepository {}
pub struct TemplateRegistry {}
pub struct ProviderRegistry {}
pub struct PolicyEngine {}

pub struct KeyOrchestrator {
    repo: KeyRepository,
    templates: TemplateRegistry,
    providers: ProviderRegistry,
    policy: PolicyEngine,
}

// TODO: Where is this orchestrator ever constructed?
impl KeyOrchestrator {
    pub fn new(
        repo: KeyRepository,
        templates: TemplateRegistry,
        providers: ProviderRegistry,
        policy: PolicyEngine,
    ) -> Self {
        Self {
            repo,
            templates,
            providers,
            policy,
        }
    }

    pub fn agc_create_key(
        self: Self,
        ctx: &mut agc_ctx,
        params: &agc_create_key_params,
        resp: &mut agc_key_info_response,
    ) -> agc_rc {
        // Validate request
        if unsafe { CStr::from_ptr(params.key_name) }.is_empty() {
            panic!("Key name must not be empty"); // TODO don't panic but throw error
        }
        // Note: in the go impl. it's policy ID.
        if unsafe { CStr::from_ptr(params.policy_name) }.is_empty() {
            panic!("Policy name must not be empty"); // TODO don't panic but throw error
        }

        // Resolve template
        if unsafe { CStr::from_ptr(params.template_id) }.is_empty() {
            // TODO use template member here 
        }

        return AGC_OK as agc_rc; // have to write it as agc_rc because bindgen inferred AGC_OK to be unsigned
    }

    pub fn agc_ctx_open(
        self: Self,
        cfg: *const agc_ctx_config,
        out_ctx: *mut *mut agc_ctx,
    ) -> agc_rc {
        return AGC_OK as agc_rc;
    }

    pub fn agc_ctx_close(self: Self, ctx: *mut agc_ctx) {
        return;
    }
}
