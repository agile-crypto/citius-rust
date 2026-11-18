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

/* The first half of the two-call convention. A call whose output regions
 * are {NULL, 0} is a size query: it does no work, answers
 * AGC_ERR_BUFFER_TOO_SMALL and sets every length the real call needs. */
static inline void size_query(agc_rc rc, const char *what)
{
    if (rc == AGC_ERR_BUFFER_TOO_SMALL)
        return;
    if (rc == AGC_OK) {
        fprintf(stderr, "%s: expected a size query, but the call succeeded\n", what);
        exit(1);
    }
    check(rc, what);
}

/* malloc that stops the example when memory runs out. */
static inline void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p && n != 0) {
        fprintf(stderr, "out of memory (%zu bytes)\n", n);
        exit(1);
    }
    return p;
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
