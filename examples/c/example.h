/* Shared by the examples: stop with the library's own message on an error. */
#ifndef AGC_EXAMPLE_H
#define AGC_EXAMPLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agilecrypto.h"

/* Prints the failed call and agc_last_error()'s message, then exits. */
static inline void check(agc_rc rc, const char *what)
{
    if (rc == AGC_OK)
        return;
    agc_error_detail d;
    AGC_INIT(&d);
    agc_last_error(&d);
    fprintf(stderr, "%s: %s (%s)\n", what, agc_rc_name(rc), d.message);
    exit(1);
}

/* A policy that allows the given templates and operations. */
static inline void add_policy(agc_ctx *ctx, const char *name, const char *document)
{
    agc_create_policy_request req;
    AGC_INIT(&req);
    req.name = name;
    req.policy_document = document;
    check(agc_create_policy(ctx, &req, NULL), "agc_create_policy");
}

#endif
