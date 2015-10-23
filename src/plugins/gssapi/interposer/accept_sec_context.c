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

OM_uint32 gssi_accept_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_cred_id_t acceptor_cred_handle,
                                  gss_buffer_t input_token_buffer,
                                  gss_channel_bindings_t input_chan_bindings,
                                  gss_name_t *src_name,
                                  gss_OID *mech_type,
                                  gss_buffer_t output_token,
                                  OM_uint32 *ret_flags,
                                  OM_uint32 *time_rec,
                                  gss_cred_id_t *delegated_cred_handle)
{
    OM_uint32 major, minor;
    gss_cred_id_t cred_handle;

    GSSI_TRACE();

    if (acceptor_cred_handle != GSS_C_NO_CREDENTIAL) {
        cred_handle = acceptor_cred_handle;
    } else {
        major = re_acquire_creds(&minor, &cred_handle);
        if (major != GSS_S_COMPLETE)
            return GSS_S_FAILURE;
    }

    major = gss_accept_sec_context(minor_status, context_handle,
                                   cred_handle,
                                   input_token_buffer, input_chan_bindings,
                                   src_name, mech_type, output_token,
                                   ret_flags, time_rec,
                                   delegated_cred_handle);

    if (acceptor_cred_handle == GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&minor, &cred_handle);
    }

    return major;
}
