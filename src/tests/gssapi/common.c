/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/gssapi/common.c - Common utility functions for GSSAPI test programs */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include "common.h"

gss_OID_desc mech_krb5 = { 9, "\052\206\110\206\367\022\001\002\002" };
gss_OID_desc mech_spnego = { 6, "\053\006\001\005\005\002" };
gss_OID_desc mech_iakerb = { 6, "\053\006\001\005\002\005" };
gss_OID_set_desc mechset_krb5 = { 1, &mech_krb5 };
gss_OID_set_desc mechset_spnego = { 1, &mech_spnego };
gss_OID_set_desc mechset_iakerb = { 1, &mech_iakerb };

static void
display_status(const char *msg, OM_uint32 code, int type)
{
    OM_uint32 min_stat, msg_ctx = 0;
    gss_buffer_desc buf;

    do {
        (void)gss_display_status(&min_stat, code, type, GSS_C_NULL_OID,
                                 &msg_ctx, &buf);
        fprintf(stderr, "%s: %.*s\n", msg, (int)buf.length, (char *)buf.value);
        (void)gss_release_buffer(&min_stat, &buf);
    } while (msg_ctx != 0);
}

void
check_gsserr(const char *msg, OM_uint32 major, OM_uint32 minor)
{
    if (GSS_ERROR(major)) {
        display_status(msg, major, GSS_C_GSS_CODE);
        display_status(msg, minor, GSS_C_MECH_CODE);
        exit(1);
    }
}

void
check_k5err(krb5_context context, const char *msg, krb5_error_code code)
{
    const char *errmsg;

    if (code) {
        errmsg = krb5_get_error_message(context, code);
        printf("%s: %s\n", msg, errmsg);
        krb5_free_error_message(context, errmsg);
        exit(1);
    }
}

void
errout(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

gss_name_t
import_name(const char *str)
{
    OM_uint32 major, minor;
    gss_name_t name;
    gss_buffer_desc buf;
    gss_OID nametype = NULL;

    if (*str == 'u')
        nametype = GSS_C_NT_USER_NAME;
    else if (*str == 'p')
        nametype = (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME;
    else if (*str == 'h')
        nametype = GSS_C_NT_HOSTBASED_SERVICE;
    if (nametype == NULL || str[1] != ':')
        errout("names must begin with u: or p: or h:");
    buf.value = (char *)str + 2;
    buf.length = strlen(str) - 2;
    major = gss_import_name(&minor, &buf, nametype, &name);
    check_gsserr("gss_import_name", major, minor);
    return name;
}

void
display_canon_name(const char *tag, gss_name_t name, gss_OID mech)
{
    gss_name_t canon;
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    major = gss_canonicalize_name(&minor, name, mech, &canon);
    check_gsserr("gss_canonicalize_name", major, minor);

    major = gss_display_name(&minor, canon, &buf, NULL);
    check_gsserr("gss_display_name", major, minor);

    printf("%s:\t%.*s\n", tag, (int)buf.length, (char *)buf.value);

    (void)gss_release_name(&minor, &canon);
    (void)gss_release_buffer(&minor, &buf);
}

void
display_oid(const char *tag, gss_OID oid)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    major = gss_oid_to_str(&minor, oid, &buf);
    check_gsserr("gss_oid_to_str", major, minor);
    if (tag != NULL)
        printf("%s:\t", tag);
    printf("%.*s\n", (int)buf.length, (char *)buf.value);
    (void)gss_release_buffer(&minor, &buf);
}

void
print_hex(FILE *fp, gss_buffer_t buf)
{
    size_t i;
    const unsigned char *bytes = buf->value;

    for (i = 0; i < buf->length; i++)
        printf("%02X", bytes[i]);
    printf("\n");
}
