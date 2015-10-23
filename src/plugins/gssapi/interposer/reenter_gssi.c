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
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "reenter.h"
#include "reenter_gssi.h"

OM_uint32 gssi_acquire_cred(OM_uint32 *minor_status,
                            const gss_name_t desired_name,
                            OM_uint32 time_req,
                            const gss_OID_set desired_mechs,
                            gss_cred_usage_t cred_usage,
                            gss_cred_id_t *output_cred_handle,
                            gss_OID_set *actual_mechs,
                            OM_uint32 *time_rec)
{
    LOG(gssi_acquire_cred);
    return gss_acquire_cred(minor_status,
                            desired_name,
                            time_req,
                            desired_mechs,
                            cred_usage,
                            output_cred_handle,
                            actual_mechs,
                            time_rec);
}


OM_uint32 gssi_acquire_cred_with_password(OM_uint32 *minor_status,
                                          const gss_name_t desired_name,
                                          const gss_buffer_t password,
                                          OM_uint32 time_req,
                                          const gss_OID_set desired_mechs,
                                          gss_cred_usage_t cred_usage,
                                          gss_cred_id_t *output_cred_handle,
                                          gss_OID_set *actual_mechs,
                                          OM_uint32 *time_rec)
{
    LOG(gssi_acquire_cred_with_password);
    return gss_acquire_cred_with_password(minor_status,
                                          desired_name,
                                          password,
                                          time_req,
                                          desired_mechs,
                                          cred_usage,
                                          output_cred_handle,
                                          actual_mechs,
                                          time_rec);
}

OM_uint32 gssi_inquire_cred(OM_uint32 *minor_status,
                            gss_cred_id_t cred_handle,
                            gss_name_t *name,
                            OM_uint32 *lifetime,
                            gss_cred_usage_t *cred_usage,
                            gss_OID_set *mechanisms)
{
    LOG(gssi_inquire_cred);
    return gss_inquire_cred(minor_status,
                            cred_handle,
                            name,
                            lifetime,
                            cred_usage,
                            mechanisms);
}

OM_uint32 gssi_inquire_cred_by_mech(OM_uint32 *minor_status,
                                    gss_cred_id_t cred_handle,
                                    gss_OID mech_type,
                                    gss_name_t *name,
                                    OM_uint32 *initiator_lifetime,
                                    OM_uint32 *acceptor_lifetime,
                                    gss_cred_usage_t *cred_usage)
{
    LOG(gssi_inquire_cred_by_mech);
    return gss_inquire_cred_by_mech(minor_status,
                                    cred_handle,
                                    mech_type,
                                    name,
                                    initiator_lifetime,
                                    acceptor_lifetime,
                                    cred_usage);
}

OM_uint32 gssi_inquire_cred_by_oid(OM_uint32 *minor_status,
	                           const gss_cred_id_t cred_handle,
	                           const gss_OID desired_object,
	                           gss_buffer_set_t *data_set)
{
    LOG(gssi_inquire_cred_by_oid);
    return gss_inquire_cred_by_oid(minor_status,
                                   cred_handle,
                                   desired_object,
                                   data_set);
}

OM_uint32 gssi_set_cred_option(OM_uint32 *minor_status,
                               gss_cred_id_t *cred_handle,
                               const gss_OID desired_object,
                               const gss_buffer_t value)
{
    LOG(gssi_set_cred_option);
    return gss_set_cred_option(minor_status,
                               cred_handle,
                               desired_object,
                               value);
}

OM_uint32 gssi_store_cred(OM_uint32 *minor_status,
                          const gss_cred_id_t input_cred_handle,
                          gss_cred_usage_t input_usage,
                          const gss_OID desired_mech,
                          OM_uint32 overwrite_cred,
                          OM_uint32 default_cred,
                          gss_OID_set *elements_stored,
                          gss_cred_usage_t *cred_usage_stored)
{
    LOG(gssi_store_cred);
    return gss_store_cred(minor_status,
                          input_cred_handle,
                          input_usage,
                          desired_mech,
                          overwrite_cred,
                          default_cred,
                          elements_stored,
                          cred_usage_stored);
}

OM_uint32 gssi_release_cred(OM_uint32 *minor_status,
                            gss_cred_id_t *cred_handle)
{
    LOG(gssi_release_cred);
    return gss_release_cred(minor_status,
                            cred_handle);
}

OM_uint32 gssi_export_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_buffer_t interprocess_token)
{
    LOG(gssi_export_sec_context);
    return gss_export_sec_context(minor_status,
                                  context_handle,
                                  interprocess_token);
}

OM_uint32 gssi_import_sec_context(OM_uint32 *minor_status,
                                  gss_buffer_t interprocess_token,
                                  gss_ctx_id_t *context_handle)
{
    LOG(gssi_import_sec_context);
    return gss_import_sec_context(minor_status,
                                  interprocess_token,
                                  context_handle);
}

OM_uint32 gssi_process_context_token(OM_uint32 *minor_status,
                                     gss_ctx_id_t context_handle,
                                     gss_buffer_t token_buffer)
{
    LOG(gssi_process_context_token);
    return gss_process_context_token(minor_status,
                                     context_handle,
                                     token_buffer);
}

OM_uint32 gssi_context_time(OM_uint32 *minor_status,
                            gss_ctx_id_t context_handle,
                            OM_uint32 *time_rec)
{
    LOG(gssi_context_time);
    return gss_context_time(minor_status,
                            context_handle,
                            time_rec);
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
    LOG(gssi_inquire_context);
    return gss_inquire_context(minor_status,
                               context_handle,
                               src_name,
                               targ_name,
                               lifetime_rec,
                               mech_type,
                               ctx_flags,
                               locally_initiated,
                               open);
}

OM_uint32 gssi_inquire_sec_context_by_oid(OM_uint32 *minor_status,
                                          const gss_ctx_id_t context_handle,
                                          const gss_OID desired_object,
                                          gss_buffer_set_t *data_set)
{
    LOG(gssi_inquire_sec_context_by_oid);
    return gss_inquire_sec_context_by_oid(minor_status,
                                          context_handle,
                                          desired_object,
                                          data_set);
}

OM_uint32 gssi_set_sec_context_option(OM_uint32 *minor_status,
                                      gss_ctx_id_t *context_handle,
                                      const gss_OID desired_object,
                                      const gss_buffer_t value)
{
    LOG(gssi_set_sec_context_option);
    return gss_set_sec_context_option(minor_status,
                                      context_handle,
                                      desired_object,
                                      value);
}

OM_uint32 gssi_pseudo_random(OM_uint32 *minor_status,
                             gss_ctx_id_t context_handle,
                             int prf_key,
                             const gss_buffer_t prf_in,
                             ssize_t desired_output_len,
                             gss_buffer_t prf_out)
{
    LOG(gssi_pseudo_random);
    return gss_pseudo_random(minor_status,
                             context_handle,
                             prf_key,
                             prf_in,
                             desired_output_len,
                             prf_out);
}

OM_uint32 gssi_delete_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_buffer_t output_token)
{
    LOG(gssi_delete_sec_context);
    return gss_delete_sec_context(minor_status,
                                  context_handle,
                                  output_token);
}

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
    LOG(gssi_accept_sec_context);
    return gss_accept_sec_context(minor_status,
                                  context_handle,
                                  acceptor_cred_handle,
                                  input_token_buffer,
                                  input_chan_bindings,
                                  src_name,
                                  mech_type,
                                  output_token,
                                  ret_flags,
                                  time_rec,
                                  delegated_cred_handle);
}

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
    LOG(gssi_init_sec_context);
    return gss_init_sec_context(minor_status,
                                claimant_cred_handle,
                                context_handle,
                                target_name,
                                mech_type,
                                req_flags,
                                time_req,
                                input_cb,
                                input_token,
                                actual_mech_type,
                                output_token,
                                ret_flags,
                                time_rec);
}

OM_uint32 gssi_display_status(OM_uint32 *minor_status,
                              OM_uint32 status_value,
                              int status_type,
                              const gss_OID mech_type,
                              OM_uint32 *message_context,
                              gss_buffer_t status_string)
{
    LOG(gssi_display_status);
    return gss_display_status(minor_status,
                              status_value,
                              status_type,
                              mech_type,
                              message_context,
                              status_string);
}

OM_uint32 gssi_display_name(OM_uint32 *minor_status,
                            gss_name_t input_name,
                            gss_buffer_t output_name_buffer,
                            gss_OID *output_name_type)
{
    LOG(gssi_display_name);
    return gss_display_name(minor_status,
                            input_name,
                            output_name_buffer,
                            output_name_type);
}

OM_uint32 gssi_display_name_ext(OM_uint32 *minor_status,
                                gss_name_t name,
                                gss_OID display_as_name_type,
                                gss_buffer_t display_name)
{
    LOG(gssi_display_name_ext);
    return gss_display_name_ext(minor_status,
                                name,
                                display_as_name_type,
                                display_name);
}

OM_uint32 gssi_import_name(OM_uint32 *minor_status,
                          gss_buffer_t input_name_buffer,
                          gss_OID input_name_type,
                          gss_name_t *output_name)
{
    LOG(gssi_import_name);
    return gss_import_name(minor_status,
                           input_name_buffer,
                           input_name_type,
                           output_name);
}

OM_uint32 gssi_release_name(OM_uint32 *minor_status,
                            gss_name_t *input_name)
{
    LOG(gssi_release_name);
    return gss_release_name(minor_status,
                            input_name);
}

OM_uint32 gssi_export_name(OM_uint32 *minor_status,
                           const gss_name_t input_name,
                           gss_buffer_t exported_name)
{
    LOG(gssi_export_name);
    return gss_export_name(minor_status,
                           input_name,
                           exported_name);
}

OM_uint32 gssi_export_name_composite(OM_uint32 *minor_status,
                                     const gss_name_t input_name,
                                     gss_buffer_t exported_composite_name)
{
    LOG(gssi_export_name_composite);
    return gss_export_name_composite(minor_status,
                                     input_name,
                                     exported_composite_name);
}

OM_uint32 gssi_duplicate_name(OM_uint32 *minor_status,
                              const gss_name_t input_name,
                              gss_name_t *dest_name)
{
    LOG(gssi_duplicate_name);
    return gss_duplicate_name(minor_status,
                              input_name,
                              dest_name);
}

OM_uint32 gssi_compare_name(OM_uint32 *minor_status,
                            gss_name_t name1,
                            gss_name_t name2,
                            int *name_equal)
{
    LOG(gssi_compare_name);
    return gss_compare_name(minor_status,
                            name1,
                            name2,
                            name_equal);
}

OM_uint32 gssi_inquire_name(OM_uint32 *minor_status,
                            gss_name_t name,
                            int *name_is_NM,
                            gss_OID *NM_mech,
                            gss_buffer_set_t *attrs)
{
    LOG(gssi_inquire_name);
    return gss_inquire_name(minor_status,
                            name,
                            name_is_NM,
                            NM_mech,
                            attrs);
}

OM_uint32 gssi_get_name_attribute(OM_uint32 *minor_status,
                                  gss_name_t input_name,
                                  gss_buffer_t attr,
                                  int *authenticated,
                                  int *complete,
                                  gss_buffer_t value,
                                  gss_buffer_t display_value,
                                  int *more)
{
    LOG(gssi_get_name_attribute);
    return gss_get_name_attribute(minor_status,
                                  input_name,
                                  attr,
                                  authenticated,
                                  complete,
                                  value,
                                  display_value,
                                  more);
}

OM_uint32 gssi_set_name_attribute(OM_uint32 *minor_status,
                                  gss_name_t input_name,
                                  int complete,
                                  gss_buffer_t attr,
                                  gss_buffer_t value)
{
    LOG(gssi_set_name_attribute);
    return gss_set_name_attribute(minor_status,
                                  input_name,
                                  complete,
                                  attr,
                                  value);
}

OM_uint32 gssi_delete_name_attribute(OM_uint32 *minor_status,
                                     gss_name_t input_name,
                                     gss_buffer_t attr)
{
    LOG(gssi_delete_name_attribute);
    return gss_delete_name_attribute(minor_status,
                                     input_name,
                                     attr);
}

OM_uint32 gssi_indicate_mechs(OM_uint32 *minor_status, gss_OID_set *mech_set)
{
    LOG(gssi_indicate_mechs);
    return gss_indicate_mechs(minor_status, mech_set);
}

OM_uint32 gssi_inquire_names_for_mech(OM_uint32 *minor_status,
                                      gss_OID mech_type,
                                      gss_OID_set *mech_names)
{
    LOG(gssi_inquire_names_for_mech);
    return gss_inquire_names_for_mech(minor_status,
                                      mech_type,
                                      mech_names);
}

OM_uint32 gssi_inquire_attrs_for_mech(OM_uint32 *minor_status,
                                      gss_OID mech,
                                      gss_OID_set *mech_attrs,
                                      gss_OID_set *known_mech_attrs)
{
    LOG(gssi_inquire_attrs_for_mech);
    return gss_inquire_attrs_for_mech(minor_status,
                                      mech,
                                      mech_attrs,
                                      known_mech_attrs);
}

OM_uint32 gssi_inquire_saslname_for_mech(OM_uint32 *minor_status,
                                         const gss_OID desired_mech,
                                         gss_buffer_t sasl_mech_name,
                                         gss_buffer_t mech_name,
                                         gss_buffer_t mech_description)
{
    LOG(gssi_inquire_saslname_for_mech);
    return gss_inquire_saslname_for_mech(minor_status,
                                         desired_mech,
                                         sasl_mech_name,
                                         mech_name,
                                         mech_description);
}

OM_uint32 gssi_inquire_mech_for_saslname(OM_uint32 *minor_status,
                                         const gss_buffer_t sasl_mech_name,
                                         gss_OID *mech_type)
{
    LOG(gssi_inquire_mech_for_saslname);
    return gss_inquire_mech_for_saslname(minor_status,
                                         sasl_mech_name,
                                         mech_type);
}

OM_uint32 gssi_wrap(OM_uint32 *minor_status,
                    gss_ctx_id_t context_handle,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    gss_buffer_t input_message_buffer,
                    int *conf_state,
                    gss_buffer_t output_message_buffer)
{
    LOG(gssi_wrap);
    return gss_wrap(minor_status,
                    context_handle,
                    conf_req_flag,
                    qop_req,
                    input_message_buffer,
                    conf_state,
                    output_message_buffer);
}

OM_uint32 gssi_wrap_size_limit(OM_uint32 *minor_status,
                               gss_ctx_id_t context_handle,
                               int conf_req_flag,
                               gss_qop_t qop_req,
                               OM_uint32 req_output_size,
                               OM_uint32 *max_input_size)
{
    LOG(gssi_wrap_size_limit);
    return gss_wrap_size_limit(minor_status,
                               context_handle,
                               conf_req_flag,
                               qop_req,
                               req_output_size,
                               max_input_size);
}

OM_uint32 gssi_wrap_iov(OM_uint32 *minor_status,
                        gss_ctx_id_t context_handle,
                        int conf_req_flag,
                        gss_qop_t qop_req,
                        int *conf_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count)
{
    LOG(gssi_wrap_iov);
    return gss_wrap_iov(minor_status,
                        context_handle,
                        conf_req_flag,
                        qop_req,
                        conf_state,
                        iov,
                        iov_count);
}

OM_uint32 gssi_wrap_iov_length(OM_uint32 *minor_status,
                               gss_ctx_id_t context_handle,
                               int conf_req_flag,
                               gss_qop_t qop_req,
                               int *conf_state,
                               gss_iov_buffer_desc *iov,
                               int iov_count)
{
    LOG(gssi_wrap_iov_length);
    return gss_wrap_iov_length(minor_status,
                               context_handle,
                               conf_req_flag,
                               qop_req,
                               conf_state,
                               iov,
                               iov_count);
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
    LOG(gssi_wrap_aead);
    return gss_wrap_aead(minor_status,
                         context_handle,
                         conf_req_flag,
                         qop_req,
                         input_assoc_buffer,
                         input_payload_buffer,
                         conf_state,
                         output_message_buffer);
}

OM_uint32 gssi_unwrap(OM_uint32 *minor_status,
                      gss_ctx_id_t context_handle,
                      gss_buffer_t input_message_buffer,
                      gss_buffer_t output_message_buffer,
                      int *conf_state,
                      gss_qop_t *qop_state)
{
    LOG(gssi_unwrap);
    return gss_unwrap(minor_status,
                      context_handle,
                      input_message_buffer,
                      output_message_buffer,
                      conf_state,
                      qop_state);
}

OM_uint32 gssi_unwrap_iov(OM_uint32 *minor_status,
                          gss_ctx_id_t context_handle,
                          int *conf_state,
                          gss_qop_t *qop_state,
                          gss_iov_buffer_desc *iov,
                          int iov_count)
{
    LOG(gssi_unwrap_iov);
    return gss_unwrap_iov(minor_status,
                          context_handle,
                          conf_state,
                          qop_state,
                          iov,
                          iov_count);
}

OM_uint32 gssi_unwrap_aead(OM_uint32 *minor_status,
                           gss_ctx_id_t context_handle,
                           gss_buffer_t input_message_buffer,
                           gss_buffer_t input_assoc_buffer,
                           gss_buffer_t output_payload_buffer,
                           int *conf_state,
                           gss_qop_t *qop_state)
{
    LOG(gssi_unwrap_aead);
    return gss_unwrap_aead(minor_status,
                           context_handle,
                           input_message_buffer,
                           input_assoc_buffer,
                           output_payload_buffer,
                           conf_state,
                           qop_state);
}

OM_uint32 gssi_get_mic(OM_uint32 *minor_status,
                       gss_ctx_id_t context_handle,
                       gss_qop_t qop_req,
                       gss_buffer_t message_buffer,
                       gss_buffer_t message_token)
{
    LOG(gssi_get_mic);
    return gss_get_mic(minor_status,
                       context_handle,
                       qop_req,
                       message_buffer,
                       message_token);
}

OM_uint32 gssi_verify_mic(OM_uint32 *minor_status,
                          gss_ctx_id_t context_handle,
                          gss_buffer_t message_buffer,
                          gss_buffer_t message_token,
                          gss_qop_t *qop_state)
{
    LOG(gssi_verify_mic);
    return gss_verify_mic(minor_status,
                          context_handle,
                          message_buffer,
                          message_token,
                          qop_state);
}
