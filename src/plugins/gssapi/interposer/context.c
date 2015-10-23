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

OM_uint32 gssi_export_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_buffer_t interprocess_token)
{
    GSSI_TRACE();
    return gss_export_sec_context(minor_status, context_handle,
                                  interprocess_token);
}

OM_uint32 gssi_import_sec_context_by_mech(OM_uint32 *minor_status,
                                          gss_OID mech_type,
                                          gss_buffer_t interprocess_token,
                                          gss_ctx_id_t *context_handle)
{
    OM_uint32 major;
    gss_buffer_desc wrap_token;
    char *buf;
    gss_OID spmech;
    uint32_t be_len;

    GSSI_TRACE();

    spmech = re_special_mech(mech_type);
    if (spmech == GSS_C_NO_OID)
        return GSS_S_FAILURE;

    wrap_token.length = sizeof(uint32_t) + spmech->length +
        interprocess_token->length;
    buf = malloc(wrap_token.length);
    if (!buf) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    wrap_token.value = buf;

    be_len = htobe32(spmech->length);
    memcpy(buf, &be_len, sizeof(uint32_t));
    memcpy(buf + sizeof(uint32_t), spmech->elements, spmech->length);
    memcpy(buf + sizeof(uint32_t) + spmech->length,
           interprocess_token->value, interprocess_token->length);
    
    major = gss_import_sec_context(minor_status, &wrap_token, context_handle);
    free(buf);
    return major;
}

OM_uint32 gssi_process_context_token(OM_uint32 *minor_status,
                                     gss_ctx_id_t context_handle,
                                     gss_buffer_t token_buffer)
{
    GSSI_TRACE();
    return gss_process_context_token(minor_status, context_handle,
                                     token_buffer);
}

OM_uint32 gssi_context_time(OM_uint32 *minor_status,
                            gss_ctx_id_t context_handle,
                            OM_uint32 *time_rec)
{
    GSSI_TRACE();
    return gss_context_time(minor_status, context_handle, time_rec);
}

OM_uint32 gssi_inquire_context(OM_uint32 *minor_status,
                               gss_ctx_id_t context_handle,
                               gss_name_t *src_name,
                               gss_name_t *targ_name,
                               OM_uint32 *lifetime_rec,
                               gss_OID *mech_type,
                               OM_uint32 *ctx_flags,
                               int *locally_initiated,
                               int *open)
{
    GSSI_TRACE();
    return gss_inquire_context(minor_status, context_handle, src_name,
                               targ_name, lifetime_rec, mech_type, ctx_flags,
                               locally_initiated, open);
}

OM_uint32 gssi_inquire_sec_context_by_oid(OM_uint32 *minor_status,
                                          const gss_ctx_id_t context_handle,
                                          const gss_OID desired_object,
                                          gss_buffer_set_t *data_set)
{
    GSSI_TRACE();
    return gss_inquire_sec_context_by_oid(minor_status, context_handle,
                                          desired_object, data_set);
}

OM_uint32 gssi_set_sec_context_option(OM_uint32 *minor_status,
                                      gss_ctx_id_t *context_handle,
                                      const gss_OID desired_object,
                                      const gss_buffer_t value)
{
    GSSI_TRACE();
    return gss_set_sec_context_option(minor_status, context_handle,
                                      desired_object, value);
}

OM_uint32 gssi_delete_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_buffer_t output_token)
{
    GSSI_TRACE();
    return gss_delete_sec_context(minor_status, context_handle, output_token);
}

OM_uint32 gssi_pseudo_random(OM_uint32 *minor_status,
                             gss_ctx_id_t context_handle,
                             int prf_key,
                             const gss_buffer_t prf_in,
                             ssize_t desired_output_len,
                             gss_buffer_t prf_out)
{
    GSSI_TRACE();
    return gss_pseudo_random(minor_status, context_handle, prf_key, prf_in,
                             desired_output_len, prf_out);
}
