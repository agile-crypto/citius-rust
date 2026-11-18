/* agc_key.h: agc_migrate_key and agc_validate_key_operation. A context has
 * one provider (rustcrypto), so from C every migration is refused; the
 * strategies themselves are tested in Rust with several providers. */
#include "agc_test.h"

static uint8_t storage[8192];

static void create_sig(agc_ctx *ctx)
{
    agc_create_key_params p = {
        .struct_size = sizeof p,
        .key_name = "sig",
        .policy_name = "default",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = AGC_SCOPE_KIND_SIGNATURE},
    };
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_OK);
}

static agc_rc migrate(agc_ctx *ctx, agc_migrate_key_params *p)
{
    agc_migrate_key_response resp;
    AGC_INIT(&resp);
    resp.want_key_info = 1;
    resp.want_report = 1;
    resp.storage = (agc_buf){storage, sizeof storage};
    return agc_migrate_key(ctx, p, &resp);
}

static void migrations_are_refused_with_reasons(agc_ctx *ctx)
{
    agc_migrate_key_params p;
    AGC_INIT(&p);
    p.key_name = "sig";
    p.strategy = AGC_MIGRATION_STRATEGY_PROVIDER_SWITCH;

    p.target.kind = AGC_MIGRATE_TARGET_INSTANCE;
    p.target.u.instance_id = "rustcrypto";
    CHECK_RC(migrate(ctx, &p), AGC_ERR_CRYPTO_MIGRATION_NOT_FEASIBLE); /* already there */
    p.target.u.instance_id = "hsm-1";
    CHECK_RC(migrate(ctx, &p), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND);

    p.target.kind = AGC_MIGRATE_TARGET_PROVIDER;
    p.target.u.provider.provider_id = "software";
    CHECK_RC(migrate(ctx, &p), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND); /* no other software provider */

    p.strategy = AGC_MIGRATION_STRATEGY_WRAPPED_TRANSFER;
    CHECK_RC(migrate(ctx, &p), AGC_ERR_NOT_IMPLEMENTED);
    p.strategy = AGC_MIGRATION_STRATEGY_UNSPECIFIED;
    CHECK_RC(migrate(ctx, &p), AGC_ERR_INVALID_ARGUMENT);

    /* Changing the algorithm is a transform, not a migration. */
    p.strategy = AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE;
    p.template_id = "ml-dsa-65";
    CHECK_RC(migrate(ctx, &p), AGC_ERR_NOT_IMPLEMENTED);
    p.template_id = NULL;

    p.target.kind = AGC_MIGRATE_TARGET_NONE;
    CHECK_RC(migrate(ctx, &p), AGC_ERR_INVALID_ARGUMENT);

    /* Nothing changed. */
    agc_key_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_read_key(ctx, "sig", 0, &r), AGC_OK);
    CHECK(r.key_info.version == 1);
}

static void validating_a_migration(agc_ctx *ctx)
{
    agc_validate_key_op_params p;
    AGC_INIT(&p);
    p.key_name = "sig";
    p.kind = AGC_VALIDATE_INTENT_MIGRATE;
    p.u.migrate.target_kind = AGC_VALIDATE_MIGRATE_TARGET_ANY;

    agc_impl_props props;
    memset(&props, 0, sizeof props);
    agc_validate_key_op_response v;
    AGC_INIT(&v);
    v.current_state.implementation_properties = &props; /* I want them */

    /* Read-only, so the size is exact: query, then call with exactly that. */
    CHECK_RC(agc_validate_key_operation(ctx, &p, &v), AGC_ERR_BUFFER_TOO_SMALL);
    size_t needed = v.storage_used;
    uint8_t *exact = malloc(needed);
    v.storage = (agc_buf){exact, needed};
    CHECK_RC(agc_validate_key_operation(ctx, &p, &v), AGC_OK);

    CHECK_STR(v.current_state.template_id, "ecdsa-p256-sha256-der");
    CHECK_STR(v.current_state.instance_id, "rustcrypto");
    CHECK_STR(v.current_state.provider_id, "software");
    CHECK(v.current_state.provider_type == AGC_PROVIDER_TYPE_SOFTWARE);
    CHECK(v.current_state.extractable == 1);
    CHECK(v.current_state.has_implementation_properties == 1);
    CHECK(v.current_state.implementation_properties == &props);
    CHECK_STR(props.implementation_language, "rust");

    CHECK(v.option_count == 5); /* every strategy assessed */
    for (size_t i = 0; i < v.option_count; i++) {
        CHECK(!v.options[i].feasible);                       /* nowhere to go */
        CHECK(strlen(v.options[i].infeasibility_reason) > 0); /* and it says why */
        CHECK(v.options[i].security_notes_count > 0);         /* what it would imply */
        CHECK(strlen(v.options[i].security_notes[0]) > 0);
    }
    CHECK(v.recommended_strategy == AGC_MIGRATION_STRATEGY_UNSPECIFIED);
    CHECK(strlen(v.recommendation_reason) > 0);
    free(exact);

    /* One strategy, on request. */
    p.u.migrate.preferred_strategy = AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE;
    v.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_validate_key_operation(ctx, &p, &v), AGC_OK);
    CHECK(v.option_count == 1 && v.options[0].strategy == AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE);
    CHECK(v.options[0].security_notes_count == 2);
    CHECK_STR(v.options[0].security_notes[0], "new material: the public key changes");
}

static void validating_a_transform(agc_ctx *ctx)
{
    agc_validate_key_op_params p;
    AGC_INIT(&p);
    p.key_name = "sig";
    p.kind = AGC_VALIDATE_INTENT_TRANSFORM;
    agc_validate_key_op_response v;
    AGC_INIT(&v);
    v.storage = (agc_buf){storage, sizeof storage};

    p.u.transform.template_id = "ml-dsa-65";
    CHECK_RC(agc_validate_key_operation(ctx, &p, &v), AGC_OK);
    CHECK(v.option_count == 1);
    CHECK(v.options[0].strategy == AGC_MIGRATION_STRATEGY_UNSPECIFIED);
    CHECK(v.options[0].feasible == 1);
    CHECK(v.options[0].security_notes_count == 0 && v.options[0].security_notes == NULL);

    p.u.transform.template_id = "ed25519"; /* not in the policy */
    CHECK_RC(agc_validate_key_operation(ctx, &p, &v), AGC_OK); /* a refusal is a result */
    CHECK(v.options[0].feasible == 0);
    CHECK(strstr(v.options[0].infeasibility_reason, "not allowed") != NULL);

    /* Retaining is a preference: ECDSA material cannot become ML-DSA, but
     * new material can be generated. */
    p.u.transform.template_id = "ml-dsa-65";
    p.u.transform.prefer_retain_bytes = 1;
    CHECK_RC(agc_validate_key_operation(ctx, &p, &v), AGC_OK);
    CHECK(v.options[0].feasible == 1);
    CHECK(strstr(v.recommendation_reason, "cannot be kept") != NULL);

    /* Assessing changed nothing. */
    agc_key_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_read_key(ctx, "sig", 0, &r), AGC_OK);
    CHECK(r.key_info.version == 1);

    p.kind = AGC_VALIDATE_INTENT_NONE;
    CHECK_RC(agc_validate_key_operation(ctx, &p, &v), AGC_ERR_INVALID_ARGUMENT);
    p.kind = AGC_VALIDATE_INTENT_TRANSFORM;
    p.key_name = "missing";
    CHECK_RC(agc_validate_key_operation(ctx, &p, &v), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    create_sig(ctx);
    migrations_are_refused_with_reasons(ctx);
    validating_a_migration(ctx);
    validating_a_transform(ctx);
    agc_ctx_close(ctx);
    return 0;
}
