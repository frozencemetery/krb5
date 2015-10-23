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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

OM_uint32 gssi_inquire_cred(OM_uint32 *minor_status,
                            gss_cred_id_t cred_handle,
                            gss_name_t *name,
                            OM_uint32 *lifetime,
                            gss_cred_usage_t *cred_usage,
                            gss_OID_set *mechanisms)
{
    GSSI_TRACE();
    return gss_inquire_cred(minor_status, cred_handle, name, lifetime,
                            cred_usage, mechanisms);
}

OM_uint32 gssi_inquire_cred_by_mech(OM_uint32 *minor_status,
                                    gss_cred_id_t cred_handle,
                                    gss_OID mech_type,
                                    gss_name_t *name,
                                    OM_uint32 *initiator_lifetime,
                                    OM_uint32 *acceptor_lifetime,
                                    gss_cred_usage_t *cred_usage)
{
    GSSI_TRACE();
    return gss_inquire_cred_by_mech(minor_status, cred_handle,
                                    re_special_mech(mech_type),
                                    name, initiator_lifetime,
                                    acceptor_lifetime, cred_usage);
}

OM_uint32 gssi_inquire_cred_by_oid(OM_uint32 *minor_status,
	                           const gss_cred_id_t cred_handle,
	                           const gss_OID desired_object,
	                           gss_buffer_set_t *data_set)
{
    GSSI_TRACE();
    return gss_inquire_cred_by_oid(minor_status, cred_handle, desired_object,
                                   data_set);
}

OM_uint32 gssi_set_cred_option(OM_uint32 *minor_status,
                               gss_cred_id_t *cred_handle,
                               const gss_OID desired_object,
                               const gss_buffer_t value)
{
    GSSI_TRACE();
    return gss_set_cred_option(minor_status, cred_handle, desired_object,
                               value);
}

/* This function is never called, but that is not specified and could
 * therefore change */
OM_uint32 gssi_store_cred(OM_uint32 *minor_status,
                          const gss_cred_id_t input_cred_handle,
                          gss_cred_usage_t input_usage,
                          const gss_OID desired_mech,
                          OM_uint32 overwrite_cred,
                          OM_uint32 default_cred,
                          gss_OID_set *elements_stored,
                          gss_cred_usage_t *cred_usage_stored)
{
    GSSI_TRACE();
    return gssi_store_cred_into(minor_status, input_cred_handle, input_usage,
                                desired_mech, overwrite_cred, default_cred,
                                NULL, elements_stored, cred_usage_stored);
}

OM_uint32 gssi_store_cred_into(OM_uint32 *minor_status,
                               const gss_cred_id_t input_cred_handle,
                               gss_cred_usage_t input_usage,
                               const gss_OID desired_mech,
                               OM_uint32 overwrite_cred,
                               OM_uint32 default_cred,
                               gss_const_key_value_set_t cred_store,
                               gss_OID_set *elements_stored,
                               gss_cred_usage_t *cred_usage_stored)
{
    GSSI_TRACE();
    return gss_store_cred_into(minor_status, input_cred_handle, input_usage,
                               re_special_mech(desired_mech),
                               overwrite_cred, default_cred, cred_store,
                               elements_stored, cred_usage_stored);
}

OM_uint32 gssi_release_cred(OM_uint32 *minor_status,
                            gss_cred_id_t *cred_handle)
{
    GSSI_TRACE();
    return gss_release_cred(minor_status, cred_handle);
}

OM_uint32 gssi_export_cred(OM_uint32 *minor_status,
                           gss_cred_id_t cred_handle,
                           gss_buffer_t token)
{
    GSSI_TRACE();
    return gss_export_cred(minor_status, cred_handle, token);
}

OM_uint32 gssi_import_cred_by_mech(OM_uint32 *minor_status,
                                   gss_OID mech_type,
                                   gss_buffer_t token,
                                   gss_cred_id_t *cred_handle)
{
    gss_OID spmech;
    gss_buffer_desc wrap_token;
    OM_uint32 maj;
    uint32_t be_len;
    char *tokbuf;

    GSSI_TRACE();

    spmech = re_special_mech(mech_type);

    wrap_token.length = sizeof(uint32_t) + spmech->length + token->length;
    tokbuf = malloc(wrap_token.length);
    if (!tokbuf) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    wrap_token.value = tokbuf;

    be_len = htobe32(wrap_token.length);
    memcpy(tokbuf, &be_len, sizeof(uint32_t));
    memcpy(tokbuf + sizeof(uint32_t), spmech->elements, spmech->length);
    memcpy(tokbuf + sizeof(uint32_t) + spmech->length,
           token->value, token->length);

    maj = gss_import_cred(minor_status, &wrap_token, cred_handle);
    free(wrap_token.value);
    return maj;
}
