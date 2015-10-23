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

OM_uint32 gssi_init_sec_context(OM_uint32 *minor_status,
                                gss_cred_id_t claimant_cred_handle,
                                gss_ctx_id_t *context_handle,
                                gss_name_t target_name,
                                gss_OID mech_type,
                                OM_uint32 req_flags,
                                OM_uint32 time_req,
                                gss_channel_bindings_t input_cb,
                                gss_buffer_t input_token,
                                gss_OID *actual_mech_type,
                                gss_buffer_t output_token,
                                OM_uint32 *ret_flags,
                                OM_uint32 *time_rec)
{
    GSSI_TRACE();
    return gss_init_sec_context(minor_status, claimant_cred_handle,
                                context_handle, target_name,
                                re_special_mech(mech_type),
                                req_flags, time_req, input_cb, input_token,
                                actual_mech_type, output_token, ret_flags,
                                time_rec);
}
