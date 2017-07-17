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

OM_uint32 gssi_wrap(OM_uint32 *minor_status,
                    gss_ctx_id_t context_handle,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    gss_buffer_t input_message_buffer,
                    int *conf_state,
                    gss_buffer_t output_message_buffer)
{
    GSSI_TRACE();
    return gss_wrap(minor_status, context_handle, conf_req_flag, qop_req,
                    input_message_buffer, conf_state, output_message_buffer);
}

OM_uint32 gssi_wrap_size_limit(OM_uint32 *minor_status,
                               gss_ctx_id_t context_handle,
                               int conf_req_flag,
                               gss_qop_t qop_req,
                               OM_uint32 req_output_size,
                               OM_uint32 *max_input_size)
{
    GSSI_TRACE();
    return gss_wrap_size_limit(minor_status, context_handle, conf_req_flag,
                               qop_req, req_output_size, max_input_size);
}

OM_uint32 gssi_wrap_iov(OM_uint32 *minor_status,
                        gss_ctx_id_t context_handle,
                        int conf_req_flag,
                        gss_qop_t qop_req,
                        int *conf_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count)
{
    GSSI_TRACE();
    return gss_wrap_iov(minor_status, context_handle, conf_req_flag, qop_req,
                        conf_state, iov, iov_count);
}

OM_uint32 gssi_wrap_iov_length(OM_uint32 *minor_status,
                               gss_ctx_id_t context_handle,
                               int conf_req_flag,
                               gss_qop_t qop_req,
                               int *conf_state,
                               gss_iov_buffer_desc *iov,
                               int iov_count)
{
    GSSI_TRACE();
    return gss_wrap_iov_length(minor_status, context_handle, conf_req_flag,
                               qop_req, conf_state, iov, iov_count);
}

OM_uint32 gssi_wrap_aead(OM_uint32 *minor_status,
	                 gss_ctx_id_t context_handle,
	                 int conf_req_flag,
	                 gss_qop_t qop_req,
	                 gss_buffer_t input_assoc_buffer,
	                 gss_buffer_t input_payload_buffer,
	                 int *conf_state,
	                 gss_buffer_t output_message_buffer)
{
    GSSI_TRACE();
    return gss_wrap_aead(minor_status, context_handle, conf_req_flag,
                         qop_req, input_assoc_buffer, input_payload_buffer,
                         conf_state, output_message_buffer);
}

OM_uint32 gssi_unwrap(OM_uint32 *minor_status,
                      gss_ctx_id_t context_handle,
                      gss_buffer_t input_message_buffer,
                      gss_buffer_t output_message_buffer,
                      int *conf_state,
                      gss_qop_t *qop_state)
{
    GSSI_TRACE();
    return gss_unwrap(minor_status, context_handle, input_message_buffer,
                      output_message_buffer, conf_state, qop_state);
}

OM_uint32 gssi_unwrap_iov(OM_uint32 *minor_status,
                          gss_ctx_id_t context_handle,
                          int *conf_state,
                          gss_qop_t *qop_state,
                          gss_iov_buffer_desc *iov,
                          int iov_count)
{
    GSSI_TRACE();
    return gss_unwrap_iov(minor_status, context_handle, conf_state, qop_state,
                          iov, iov_count);
}

OM_uint32 gssi_unwrap_aead(OM_uint32 *minor_status,
                           gss_ctx_id_t context_handle,
                           gss_buffer_t input_message_buffer,
                           gss_buffer_t input_assoc_buffer,
                           gss_buffer_t output_payload_buffer,
                           int *conf_state,
                           gss_qop_t *qop_state)
{
    GSSI_TRACE();
    return gss_unwrap_aead(minor_status, context_handle, input_message_buffer,
                           input_assoc_buffer, output_payload_buffer,
                           conf_state, qop_state);
}

OM_uint32 gssi_get_mic(OM_uint32 *minor_status,
                       gss_ctx_id_t context_handle,
                       gss_qop_t qop_req,
                       gss_buffer_t message_buffer,
                       gss_buffer_t message_token)
{
    GSSI_TRACE();
    return gss_get_mic(minor_status, context_handle, qop_req, message_buffer,
                       message_token);
}

OM_uint32 gssi_verify_mic(OM_uint32 *minor_status,
                          gss_ctx_id_t context_handle,
                          gss_buffer_t message_buffer,
                          gss_buffer_t message_token,
                          gss_qop_t *qop_state)
{
    GSSI_TRACE();
    return gss_verify_mic(minor_status, context_handle, message_buffer,
                          message_token, qop_state);
}

OM_uint32 gssi_get_mic_iov(OM_uint32 *minor_status,
                           gss_ctx_id_t context_handle, gss_qop_t qop_req,
                           gss_iov_buffer_desc *iov, int iov_count)
{
    GSSI_TRACE();
    return gss_get_mic_iov(minor_status, context_handle, qop_req, iov,
                           iov_count);
}

OM_uint32 gssi_get_mic_iov_length(OM_uint32 *minor_status,
                                  gss_ctx_id_t context_handle,
                                  gss_qop_t qop_req, gss_iov_buffer_desc *iov,
                                  int iov_count)
{
    GSSI_TRACE();
    return gss_get_mic_iov_length(minor_status, context_handle, qop_req, iov,
                                  iov_count);
}

OM_uint32 gssi_verify_mic_iov(OM_uint32 *minor_status,
                              gss_ctx_id_t context_handle,
                              gss_qop_t *qop_state, gss_iov_buffer_desc *iov,
                              int iov_count)
{
    GSSI_TRACE();
    return gss_verify_mic_iov(minor_status, context_handle, qop_state, iov,
                              iov_count);
}
