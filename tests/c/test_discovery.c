/* agc_discovery.h and the read half of agc_provider.h. */
#include "agc_test.h"

static uint8_t storage[1 << 16];

static agc_template_info_response template_response(size_t cap)
{
    agc_template_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){storage, cap};
    return r;
}

static void get_template(agc_ctx *ctx)
{
    agc_template_info_response r = template_response(sizeof storage);
    CHECK_RC(agc_get_template(ctx, "ed25519", &r), AGC_OK);
    const agc_template_info *t = &r.template_info;
    CHECK_STR(t->template_id, "ed25519");
    CHECK(t->algorithm.params.kind == AGC_ALGORITHM_ED25519);
    CHECK(t->algorithm.params.u.ed25519.variant == AGC_ED25519_VARIANT_PURE);
    CHECK_STR(t->algorithm.oid, "1.3.101.112");
    CHECK(t->status == AGC_TEMPLATE_STATUS_ACTIVE);
    CHECK(t->scoped_capabilities_count == 1);
    const agc_scoped_capabilities *c = &t->scoped_capabilities[0];
    CHECK(c->scope.kind == AGC_SCOPE_KIND_SIGNATURE);
    CHECK(c->scope.u.signature.scope == AGC_SIGNATURE_SCOPE_STANDARD);
    CHECK(c->scope.u.signature.deterministic == AGC_TRUE);
    CHECK(c->operations_count == 2);
    CHECK(c->operations[0] == AGC_CRYPTO_OPERATION_SIGN && c->operations[1] == AGC_CRYPTO_OPERATION_VERIFY);
    CHECK(c->has_security_guarantees && c->security_guarantees.formal.suf_cma == AGC_TRUE);
    CHECK(c->security_guarantees.formal.ind_cpa == AGC_UNSET); /* the catalog makes no claim */
    CHECK(t->standards_count == 2);
    CHECK_STR(t->standards[0], "RFC 8032");

    /* A hybrid: components are nested algorithms in the same storage. */
    r = template_response(sizeof storage);
    CHECK_RC(agc_get_template(ctx, "hybrid-x25519-mlkem768-concat", &r), AGC_OK);
    const agc_hybrid_algorithm_params *h = &r.template_info.algorithm.params.u.hybrid;
    CHECK(r.template_info.algorithm.params.kind == AGC_ALGORITHM_HYBRID);
    CHECK(h->components_count == 2);
    CHECK(h->components[0].algorithm->params.kind == AGC_ALGORITHM_X25519);
    CHECK_STR(h->components[0].label, "classical");
    CHECK(h->components[1].algorithm->params.kind == AGC_ALGORITHM_ML_KEM);
    CHECK(h->components[1].algorithm->params.u.ml_kem.parameter_set == AGC_ML_KEM_768);
    CHECK(h->components[1].order == 2);

    /* Size query: storage_used set, nothing else written. */
    r = template_response(0);
    r.storage.data = NULL;
    CHECK_RC(agc_get_template(ctx, "ed25519", &r), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(r.storage_used > 0 && r.template_info.template_id == NULL);

    r = template_response(sizeof storage);
    CHECK_RC(agc_get_template(ctx, "no-such-template", &r), AGC_ERR_CRYPTO_TEMPLATE_NOT_FOUND);
    CHECK_RC(agc_get_template(ctx, NULL, &r), AGC_ERR_INVALID_ARGUMENT);
}

static void list_templates(agc_ctx *ctx)
{
    agc_list_templates_params p;
    AGC_INIT(&p);
    agc_template_iter *it = NULL;
    CHECK_RC(agc_list_templates(ctx, &p, &it), AGC_OK);
    agc_template_info_response r = template_response(16); /* deliberately small */
    size_t n = 0;
    char previous[128] = "";
    for (;;) {
        agc_rc rc = agc_template_iter_next(it, &r);
        if (rc == AGC_ERR_ITERATOR_EXHAUSTED)
            break;
        if (rc == AGC_ERR_BUFFER_TOO_SMALL) { /* grow, retry the same template */
            CHECK(r.storage_used <= sizeof storage);
            r.storage.cap = r.storage_used;
            continue;
        }
        CHECK_RC(rc, AGC_OK);
        CHECK(strcmp(previous, r.template_info.template_id) < 0); /* ordered by id */
        snprintf(previous, sizeof previous, "%s", r.template_info.template_id);
        n++;
    }
    agc_template_iter_free(it);
    CHECK(n == 72);

    /* Filters: statuses and standards. */
    agc_template_status acceptable = AGC_TEMPLATE_STATUS_ACCEPTABLE;
    p.allowed_statuses = &acceptable;
    p.allowed_statuses_count = 1;
    CHECK_RC(agc_list_templates(ctx, &p, &it), AGC_OK);
    for (n = 0, r = template_response(sizeof storage); agc_template_iter_next(it, &r) == AGC_OK; n++)
        CHECK(r.template_info.status == AGC_TEMPLATE_STATUS_ACCEPTABLE);
    agc_template_iter_free(it);
    CHECK(n == 8);

    AGC_INIT(&p);
    agc_str standards[] = {"RFC 8032"};
    p.required_standards = (agc_str_list){standards, 1};
    agc_scope_spec prehashed = {.struct_size = sizeof prehashed, .kind = AGC_SCOPE_KIND_SIGNATURE,
                                .u.signature.scope = AGC_SIGNATURE_SCOPE_PREHASHED};
    p.scope_spec = &prehashed;
    CHECK_RC(agc_list_templates(ctx, &p, &it), AGC_OK);
    r = template_response(sizeof storage);
    CHECK_RC(agc_template_iter_next(it, &r), AGC_OK);
    CHECK_STR(r.template_info.template_id, "ed25519ph");
    CHECK_RC(agc_template_iter_next(it, &r), AGC_ERR_ITERATOR_EXHAUSTED);
    agc_template_iter_free(it);
}

static void list_scopes(agc_ctx *ctx)
{
    agc_list_scopes_response r;
    AGC_INIT(&r); /* array NULL: a size query on both */
    CHECK_RC(agc_list_scopes(ctx, &r), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(r.scopes_count > 0 && r.storage_used > 0);
    agc_scope_info scopes[64];
    CHECK(r.scopes_count <= 64);
    r.scopes = scopes;
    r.scopes_cap = r.scopes_count;
    r.storage = (agc_buf){storage, r.storage_used};
    CHECK_RC(agc_list_scopes(ctx, &r), AGC_OK);
    /* Go's names, Go's order: signature scopes first. */
    CHECK_STR(scopes[0].name, "signature_standard");
    CHECK(scopes[0].specification.kind == AGC_SCOPE_KIND_SIGNATURE);
    CHECK(scopes[0].supported_operations_count == 2);
    int saw_aead = 0;
    for (size_t i = 0; i < r.scopes_count; i++)
        saw_aead |= strcmp(scopes[i].name, "aead_standard") == 0;
    CHECK(saw_aead);

    r.scopes_cap = 1; /* too small: count and storage reported, nothing written */
    scopes[0].name = NULL;
    CHECK_RC(agc_list_scopes(ctx, &r), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(r.scopes_count > 1 && scopes[0].name == NULL);
}

static void providers(agc_ctx *ctx)
{
    agc_list_providers_request lr;
    AGC_INIT(&lr);
    lr.template_id = "ed25519";
    agc_provider_iter *it = NULL;
    CHECK_RC(agc_list_providers(ctx, &lr, &it), AGC_OK);
    agc_provider_info_response pr;
    AGC_INIT(&pr);
    pr.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_provider_iter_next(it, &pr), AGC_OK);
    CHECK_STR(pr.provider.provider_id, "software");
    CHECK(pr.provider.template_support_count == 22);
    CHECK_RC(agc_provider_iter_next(it, &pr), AGC_ERR_ITERATOR_EXHAUSTED);
    agc_provider_iter_free(it);

    CHECK_RC(agc_get_provider(ctx, "software", &pr), AGC_OK);
    CHECK_STR(pr.provider.template_support[0].notes, "instances: rustcrypto");
    CHECK_RC(agc_get_provider(ctx, "hsm", &pr), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND);

    /* Requirements filter: nothing is FIPS certified here. */
    agc_provider_requirements fips;
    AGC_INIT(&fips);
    fips.fips_140_certified = AGC_TRUE;
    lr.requirements = &fips;
    CHECK_RC(agc_list_providers(ctx, &lr, &it), AGC_OK);
    CHECK_RC(agc_provider_iter_next(it, &pr), AGC_ERR_ITERATOR_EXHAUSTED);
    agc_provider_iter_free(it);
}

static void instances(agc_ctx *ctx)
{
    agc_list_provider_instances_request lr;
    AGC_INIT(&lr);
    agc_provider_instance_iter *it = NULL;
    CHECK_RC(agc_list_provider_instances(ctx, &lr, &it), AGC_OK);
    agc_provider_instance_response ir;
    AGC_INIT(&ir);
    ir.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_provider_instance_iter_next(it, &ir), AGC_OK);
    CHECK_STR(ir.instance.instance_id, "rustcrypto");
    CHECK_STR(ir.instance.provider_id, "software");
    CHECK(ir.instance.disabled == 0);
    CHECK(ir.instance.has_implementation_override);
    CHECK(ir.instance.implementation_override.memory_safe_language == AGC_TRUE);
    CHECK_STR(ir.instance.implementation_override.implementation_language, "rust");
    CHECK_RC(agc_provider_instance_iter_next(it, &ir), AGC_ERR_ITERATOR_EXHAUSTED);
    agc_provider_instance_iter_free(it);

    CHECK_RC(agc_get_provider_instance(ctx, "rustcrypto", &ir), AGC_OK);
    CHECK_RC(agc_get_provider_instance(ctx, "nope", &ir), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND);
    CHECK_RC(agc_get_provider_instance(ctx, "", &ir), AGC_ERR_INVALID_ARGUMENT);
}

static void match(agc_ctx *ctx)
{
    agc_match_providers_request mr;
    AGC_INIT(&mr);
    mr.template_id = "aes-128-gcm-128-96";
    agc_match_providers_response r;
    AGC_INIT(&r);
    CHECK_RC(agc_match_providers(ctx, &mr, &r), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(r.matches_count == 1 && r.storage_used > 0);
    agc_matched_provider m[4];
    r.matches = m;
    r.matches_cap = 4;
    r.storage = (agc_buf){storage, r.storage_used}; /* exact */
    CHECK_RC(agc_match_providers(ctx, &mr, &r), AGC_OK);
    CHECK_STR(m[0].instance.instance_id, "rustcrypto");
    CHECK(m[0].match_score == 1 && m[0].has_resolved_implementation);

    /* The first match is the provider create_key picks. */
    agc_create_key_params p = AEAD_KEY_PARAMS("matched");
    uint8_t ks[2048];
    agc_key_info_response kr;
    AGC_INIT(&kr);
    kr.storage = (agc_buf){ks, sizeof ks};
    CHECK_RC(agc_create_key(ctx, &p, &kr), AGC_OK);
    CHECK_STR(kr.key_info.provider_id, m[0].instance.instance_id);

    mr.template_id = "not-a-template";
    CHECK_RC(agc_match_providers(ctx, &mr, &r), AGC_OK);
    CHECK(r.matches_count == 0);
    mr.template_id = NULL;
    CHECK_RC(agc_match_providers(ctx, &mr, &r), AGC_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    get_template(ctx);
    list_templates(ctx);
    list_scopes(ctx);
    providers(ctx);
    instances(ctx);
    match(ctx);
    agc_ctx_close(ctx);
    puts("test_discovery: ok");
    return 0;
}
