/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* This code is adapted from the GSS-Proxy project */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2011-2017 the GSS-PROXY contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "reenter_gssi.h"

#include "autoconf.h"
#include "gssapiP_krb5.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

gss_OID_desc gpoid_krb5 = {
    .length = GSS_MECH_KRB5_OID_LENGTH,
    .elements = GSS_MECH_KRB5_OID
};
gss_OID_desc gpoid_krb5_old = {
    .length = GSS_MECH_KRB5_OLD_OID_LENGTH,
    .elements = GSS_MECH_KRB5_OLD_OID
};
gss_OID_desc gpoid_krb5_wrong = {
    .length = GSS_MECH_KRB5_WRONG_OID_LENGTH,
    .elements = GSS_MECH_KRB5_WRONG_OID
};
gss_OID_desc gpoid_iakerb = {
    .length = GSS_MECH_IAKERB_OID_LENGTH,
    .elements = GSS_MECH_IAKERB_OID
};

/* 2.16.840.1.113730.3.8.15.1 */
const gss_OID_desc gssproxy_mech_interposer = {
    .length = 11,
    .elements = "\140\206\110\001\206\370\102\003\010\017\001"
};

struct mech_mapping_elt {
    gss_OID_desc real_oid;
    gss_OID_desc fake_oid;
    struct mech_mapping_elt *next;
};
struct mech_mapping_elt *mech_mapping = NULL;
pthread_rwlock_t mech_mapping_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct mech_mapping_elt *re_new_special_mech(gss_OID real)
{
    struct mech_mapping_elt *new;

    new = calloc(1, sizeof(struct mech_mapping_elt));
    if (!new)
        return NULL;

    new->real_oid.length = real->length;
    new->fake_oid.length = real->length + gssproxy_mech_interposer.length;

    new->real_oid.elements = malloc(real->length);
    new->fake_oid.elements = malloc(new->fake_oid.length);
    if (!new->real_oid.elements || !new->fake_oid.elements) {
        free(new->real_oid.elements);
        free(new->fake_oid.elements);
        free(new);
        return NULL;
    }

    memcpy(new->real_oid.elements, real->elements, real->length);
    memcpy(new->fake_oid.elements, gssproxy_mech_interposer.elements,
           gssproxy_mech_interposer.length);
    memcpy((char *) new->fake_oid.elements + gssproxy_mech_interposer.length,
           real->elements, real->length);

    return new;
}

static int is_special_oid(const gss_OID mech_type)
{
    if (mech_type != GSS_C_NO_OID &&
        mech_type->length >= gssproxy_mech_interposer.length &&
        memcmp(gssproxy_mech_interposer.elements,
               mech_type->elements,
               gssproxy_mech_interposer.length) == 0) {
        return 1;
    }
    return 0;
}

const gss_OID re_special_mech(gss_OID real)
{
    int res;
    struct mech_mapping_elt *cur, *new;
    gss_OID ret_oid = GSS_C_NO_OID;

    if (is_special_oid(real))
        return real;
    
    do {
        res = pthread_rwlock_rdlock(&mech_mapping_lock);
    } while (res == EAGAIN);
    assert(res == 0);

    for (cur = mech_mapping; cur != NULL && cur->next != NULL;
         cur = cur->next) {
        if (gss_oid_equal(real, &cur->real_oid)) {
            ret_oid = &cur->fake_oid;
            goto done;
        }
    }
    pthread_rwlock_unlock(&mech_mapping_lock);

    /* No OID found, so try to make one */
    do {
        res = pthread_rwlock_wrlock(&mech_mapping_lock);
    } while (res == EAGAIN);
    assert(res == 0);

    /* it may have been created while we were blocking */
    for (cur = mech_mapping; cur != NULL && cur->next != NULL;
         cur = cur->next) {
        if (gss_oid_equal(real, &cur->real_oid)) {
            ret_oid = &cur->fake_oid;
            goto done;
        }
    }

    new = re_new_special_mech(real);
    if (!new)
        goto done;

    if (cur == NULL)
        mech_mapping = new;
    else
        cur->next = new;
    ret_oid = &new->fake_oid;

done:
    pthread_rwlock_unlock(&mech_mapping_lock);
    return ret_oid;
}

gss_OID_set re_special_mechs(const gss_OID_set mechs)
{
    OM_uint32 major, minor;
    gss_OID_set spmechs;
    gss_OID special;
    unsigned i;

    major = gss_create_empty_oid_set(&minor, &spmechs);
    if (major)
        return GSS_C_NO_OID_SET;

    for (i = 0; i < mechs->count; i++) {
        special = re_special_mech(&mechs->elements[i]);
        if (special == GSS_C_NO_OID)
            goto fail;

        major = gss_add_oid_set_member(&minor, special, &spmechs);
        if (major != GSS_S_COMPLETE)
            goto fail;
    }

    return spmechs;    
fail:
    gss_release_oid_set(&minor, &spmechs);
    return GSS_C_NO_OID_SET;
}

OM_uint32 re_acquire_creds(OM_uint32 *minor, gss_cred_id_t *handle)
{
    gss_OID_set interposed_mechs, special_mechs;

    interposed_mechs = gss_mech_interposer((gss_OID)&gssproxy_mech_interposer);
    if (interposed_mechs == GSS_C_NO_OID_SET)
        return GSS_S_FAILURE;

    special_mechs = re_special_mechs(interposed_mechs);
    if (special_mechs == GSS_C_NO_OID_SET)
        return GSS_S_FAILURE;

    return gss_acquire_cred(minor, NULL, 0, special_mechs, GSS_C_ACCEPT,
                            handle, NULL, NULL);
}

gss_OID_set gss_mech_interposer(gss_OID mech_type)
{
    gss_OID_set_desc *interposed_mechs = NULL;
    OM_uint32 maj, min;

    GSSI_TRACE();

    if (!gss_oid_equal(&gssproxy_mech_interposer, mech_type)) {
        return NULL;
    }

    maj = gss_create_empty_oid_set(&min, &interposed_mechs);
    if (maj != 0) {
        return NULL;
    }

    maj = gss_add_oid_set_member(&min, &gpoid_krb5,
                                 &interposed_mechs);
    if (maj != 0) {
        goto done;
    }
    maj = gss_add_oid_set_member(&min, &gpoid_krb5_old,
                                 &interposed_mechs);
    if (maj != 0) {
        goto done;
    }
    maj = gss_add_oid_set_member(&min, &gpoid_krb5_wrong,
                                 &interposed_mechs);
    if (maj != 0) {
        goto done;
    }
    maj = gss_add_oid_set_member(&min, &gpoid_iakerb,
                                 &interposed_mechs);
    if (maj != 0) {
        goto done;
    }

done:
    if (maj != 0) {
        fprintf(stderr, "%s\n", "failed to initialize mechlist");
        gss_release_oid_set(&min, &interposed_mechs);
        interposed_mechs = NULL;
    }
    return interposed_mechs;
}
