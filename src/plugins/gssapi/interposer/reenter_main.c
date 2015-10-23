/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Red Hat, Inc., nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "autoconf.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "reenter.h"

#define no_const(ptr) ((void *)((uintptr_t)(ptr)))

/* 2.16.840.1.113730.3.8.15.1 */
const gss_OID_desc gssproxy_mech_interposer = {
    .length = 11,
    .elements = "\140\206\110\001\206\370\102\003\010\017\001"
};

#define KRB5_OID_LEN 9
#define KRB5_OID "\052\206\110\206\367\022\001\002\002"

#define KRB5_OLD_OID_LEN 5
#define KRB5_OLD_OID "\053\005\001\005\002"

/* Incorrect krb5 mech OID emitted by MS. */
#define KRB5_WRONG_OID_LEN 9
#define KRB5_WRONG_OID "\052\206\110\202\367\022\001\002\002"

#define IAKERB_OID_LEN 6
#define IAKERB_OID "\053\006\001\005\002\005"

const gss_OID_desc gpoid_krb5 = {
    .length = KRB5_OID_LEN,
    .elements = KRB5_OID
};
const gss_OID_desc gpoid_krb5_old = {
    .length = KRB5_OLD_OID_LEN,
    .elements = KRB5_OLD_OID
};
const gss_OID_desc gpoid_krb5_wrong = {
    .length = KRB5_WRONG_OID_LEN,
    .elements = KRB5_WRONG_OID
};
const gss_OID_desc gpoid_iakerb = {
    .length = IAKERB_OID_LEN,
    .elements = IAKERB_OID
};


gss_OID_set gss_mech_interposer(gss_OID mech_type)
{
    gss_OID_set interposed_mechs;
    OM_uint32 maj, min;

    LOG(gss_mech_interposer);

    interposed_mechs = NULL;
    maj = 0;
    if (gss_oid_equal(&gssproxy_mech_interposer, mech_type)) {
        maj = gss_create_empty_oid_set(&min, &interposed_mechs);
        if (maj != 0) {
            return NULL;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5_old),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5_wrong),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_iakerb),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
    }

done:
    if (maj != 0) {
        (void)gss_release_oid_set(&min, &interposed_mechs);
        interposed_mechs = NULL;
    }

    return interposed_mechs;
}
