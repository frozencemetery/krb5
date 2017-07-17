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

#ifndef _REENTER_GSSI_H
#define _REENTER_GSSI_H

#include <stdio.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#define GSSI_TRACE() \
    do { \
        fprintf(stderr, "reenter_gssi: %s\n", __FUNCTION__); \
        fflush(stderr); \
    } while (0);

/* reenter_gssi.c */
const gss_OID re_special_mech(gss_OID real);
gss_OID_set re_special_mechs(const gss_OID_set mechs);
OM_uint32 re_acquire_creds(OM_uint32 *minor, gss_cred_id_t *handle);
gss_OID_set gss_mech_interposer(gss_OID mech_type);

/* acquire_cred.c */
OM_uint32 gssi_acquire_cred(OM_uint32 *minor_status,
                            const gss_name_t desired_name,
                            OM_uint32 time_req,
                            const gss_OID_set desired_mechs,
                            gss_cred_usage_t cred_usage,
                            gss_cred_id_t *output_cred_handle,
                            gss_OID_set *actual_mechs,
                            OM_uint32 *time_rec);

OM_uint32 gssi_acquire_cred_from(OM_uint32 *minor_status,
                                 const gss_name_t desired_name,
                                 OM_uint32 time_req,
                                 const gss_OID_set desired_mechs,
                                 gss_cred_usage_t cred_usage,
                                 gss_const_key_value_set_t cred_store,
                                 gss_cred_id_t *output_cred_handle,
                                 gss_OID_set *actual_mechs,
                                 OM_uint32 *time_rec);

OM_uint32 gssi_add_cred(OM_uint32 *minor_status,
                        const gss_cred_id_t input_cred_handle,
                        const gss_name_t desired_name,
                        const gss_OID desired_mech,
                        gss_cred_usage_t cred_usage,
                        OM_uint32 initiator_time_req,
                        OM_uint32 acceptor_time_req,
                        gss_cred_id_t *output_cred_handle,
                        gss_OID_set *actual_mechs,
                        OM_uint32 *initiator_time_rec,
                        OM_uint32 *acceptor_time_rec);

OM_uint32 gssi_add_cred_from(OM_uint32 *minor_status,
                             const gss_cred_id_t input_cred_handle,
                             const gss_name_t desired_name,
                             const gss_OID desired_mech,
                             gss_cred_usage_t cred_usage,
                             OM_uint32 initiator_time_req,
                             OM_uint32 acceptor_time_req,
                             gss_const_key_value_set_t cred_store,
                             gss_cred_id_t *output_cred_handle,
                             gss_OID_set *actual_mechs,
                             OM_uint32 *initiator_time_rec,
                             OM_uint32 *acceptor_time_rec);

OM_uint32 gssi_acquire_cred_with_password(OM_uint32 *minor_status,
                                          const gss_name_t desired_name,
                                          const gss_buffer_t password,
                                          OM_uint32 time_req,
                                          const gss_OID_set desired_mechs,
                                          gss_cred_usage_t cred_usage,
                                          gss_cred_id_t *output_cred_handle,
                                          gss_OID_set *actual_mechs,
                                          OM_uint32 *time_rec);

OM_uint32 gssi_acquire_cred_impersonate_name(OM_uint32 *minor_status,
                                             gss_cred_id_t imp_cred_handle,
                                             const gss_name_t desired_name,
                                             OM_uint32 time_req,
                                             const gss_OID_set desired_mechs,
                                             gss_cred_usage_t cred_usage,
                                             gss_cred_id_t *output_cred_handle,
                                             gss_OID_set *actual_mechs,
                                             OM_uint32 *time_rec);

/* creds.c */
OM_uint32 gssi_inquire_cred(OM_uint32 *minor_status,
                            gss_cred_id_t cred_handle,
                            gss_name_t *name,
                            OM_uint32 *lifetime,
                            gss_cred_usage_t *cred_usage,
                            gss_OID_set *mechanisms);

OM_uint32 gssi_inquire_cred_by_mech(OM_uint32 *minor_status,
                                    gss_cred_id_t cred_handle,
                                    gss_OID mech_type,
                                    gss_name_t *name,
                                    OM_uint32 *initiator_lifetime,
                                    OM_uint32 *acceptor_lifetime,
                                    gss_cred_usage_t *cred_usage);

OM_uint32 gssi_inquire_cred_by_oid(OM_uint32 *minor_status,
	                           const gss_cred_id_t cred_handle,
	                           const gss_OID desired_object,
	                           gss_buffer_set_t *data_set);

OM_uint32 gssi_set_cred_option(OM_uint32 *minor_status,
                               gss_cred_id_t *cred_handle,
                               const gss_OID desired_object,
                               const gss_buffer_t value);

OM_uint32 gssi_export_cred(OM_uint32 *minor_status,
                           gss_cred_id_t cred_handle,
                           gss_buffer_t token);

OM_uint32 gssi_import_cred_by_mech(OM_uint32 *minor_status,
                                   gss_OID mech_type,
                                   gss_buffer_t token,
                                   gss_cred_id_t *cred_handle);

OM_uint32 gssi_store_cred(OM_uint32 *minor_status,
                          const gss_cred_id_t input_cred_handle,
                          gss_cred_usage_t input_usage,
                          const gss_OID desired_mech,
                          OM_uint32 overwrite_cred,
                          OM_uint32 default_cred,
                          gss_OID_set *elements_stored,
                          gss_cred_usage_t *cred_usage_stored);

OM_uint32 gssi_store_cred_into(OM_uint32 *minor_status,
                               const gss_cred_id_t input_cred_handle,
                               gss_cred_usage_t input_usage,
                               const gss_OID desired_mech,
                               OM_uint32 overwrite_cred,
                               OM_uint32 default_cred,
                               gss_const_key_value_set_t cred_store,
                               gss_OID_set *elements_stored,
                               gss_cred_usage_t *cred_usage_stored);

OM_uint32 gssi_release_cred(OM_uint32 *minor_status,
                            gss_cred_id_t *cred_handle);

/* context.c */
OM_uint32 gssi_export_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_buffer_t interprocess_token);

OM_uint32 gssi_import_sec_context_by_mech(OM_uint32 *minor_status,
                                          gss_OID mech_type,
                                          gss_buffer_t interprocess_token,
                                          gss_ctx_id_t *context_handle);

OM_uint32 gssi_process_context_token(OM_uint32 *minor_status,
                                     gss_ctx_id_t context_handle,
                                     gss_buffer_t token_buffer);

OM_uint32 gssi_context_time(OM_uint32 *minor_status,
                            gss_ctx_id_t context_handle,
                            OM_uint32 *time_rec);

OM_uint32 gssi_inquire_context(OM_uint32 *minor_status,
                               gss_ctx_id_t context_handle,
                               gss_name_t *src_name,
                               gss_name_t *targ_name,
                               OM_uint32 *lifetime_rec,
                               gss_OID *mech_type,
                               OM_uint32 *ctx_flags,
                               int *locally_initiated,
                               int *open);

OM_uint32 gssi_inquire_sec_context_by_oid(OM_uint32 *minor_status,
                                          const gss_ctx_id_t context_handle,
                                          const gss_OID desired_object,
                                          gss_buffer_set_t *data_set);

OM_uint32 gssi_set_sec_context_option(OM_uint32 *minor_status,
                                      gss_ctx_id_t *context_handle,
                                      const gss_OID desired_object,
                                      const gss_buffer_t value);

OM_uint32 gssi_pseudo_random(OM_uint32 *minor_status,
                             gss_ctx_id_t context_handle,
                             int prf_key,
                             const gss_buffer_t prf_in,
                             ssize_t desired_output_len,
                             gss_buffer_t prf_out);

OM_uint32 gssi_delete_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_buffer_t output_token);

/* accept_sec_context.c */
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
                                  gss_cred_id_t *delegated_cred_handle);

/* init_sec_context.c */
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
                                OM_uint32 *time_rec);

/* display_status.c */
OM_uint32 gssi_display_status(OM_uint32 *minor_status,
                              OM_uint32 status_value,
                              int status_type,
                              const gss_OID mech_type,
                              OM_uint32 *message_context,
                              gss_buffer_t status_string);

/* import_and_canon_name.c */
OM_uint32 gssi_display_name(OM_uint32 *minor_status,
                            gss_name_t input_name,
                            gss_buffer_t output_name_buffer,
                            gss_OID *output_name_type);

OM_uint32 gssi_display_name_ext(OM_uint32 *minor_status,
                                gss_name_t name,
                                gss_OID display_as_name_type,
                                gss_buffer_t display_name);

OM_uint32 gssi_import_name_by_mech(OM_uint32 *minor_status,
                                   gss_OID mech_type,
                                   gss_buffer_t input_name_buffer,
                                   gss_OID input_name_type,
                                   gss_name_t *output_name);

OM_uint32 gssi_release_name(OM_uint32 *minor_status,
                            gss_name_t *input_name);

OM_uint32 gssi_export_name(OM_uint32 *minor_status,
                           const gss_name_t input_name,
                           gss_buffer_t exported_name);

OM_uint32 gssi_export_name_composite(OM_uint32 *minor_status,
                                     const gss_name_t input_name,
                                     gss_buffer_t exported_composite_name);

OM_uint32 gssi_duplicate_name(OM_uint32 *minor_status,
                              const gss_name_t input_name,
                              gss_name_t *dest_name);

OM_uint32 gssi_compare_name(OM_uint32 *minor_status,
                            gss_name_t name1,
                            gss_name_t name2,
                            int *name_equal);

OM_uint32 gssi_inquire_name(OM_uint32 *minor_status,
                            gss_name_t name,
                            int *name_is_NM,
                            gss_OID *NM_mech,
                            gss_buffer_set_t *attrs);

OM_uint32 gssi_get_name_attribute(OM_uint32 *minor_status,
                                  gss_name_t input_name,
                                  gss_buffer_t attr,
                                  int *authenticated,
                                  int *complete,
                                  gss_buffer_t value,
                                  gss_buffer_t display_value,
                                  int *more);

OM_uint32 gssi_set_name_attribute(OM_uint32 *minor_status,
                                  gss_name_t input_name,
                                  int complete,
                                  gss_buffer_t attr,
                                  gss_buffer_t value);

OM_uint32 gssi_delete_name_attribute(OM_uint32 *minor_status,
                                     gss_name_t input_name,
                                     gss_buffer_t attr);

/* indicate_mechs.c */
OM_uint32 gssi_inquire_names_for_mech(OM_uint32 *minor_status,
                                      gss_OID mech_type,
                                      gss_OID_set *mech_names);

OM_uint32 gssi_inquire_attrs_for_mech(OM_uint32 *minor_status,
                                      gss_OID mech,
                                      gss_OID_set *mech_attrs,
                                      gss_OID_set *known_mech_attrs);

OM_uint32 gssi_inquire_saslname_for_mech(OM_uint32 *minor_status,
                                         const gss_OID desired_mech,
                                         gss_buffer_t sasl_mech_name,
                                         gss_buffer_t mech_name,
                                         gss_buffer_t mech_description);

/* priv_integ.c */
OM_uint32 gssi_wrap(OM_uint32 *minor_status,
                    gss_ctx_id_t context_handle,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    gss_buffer_t input_message_buffer,
                    int *conf_state,
                    gss_buffer_t output_message_buffer);

OM_uint32 gssi_wrap_size_limit(OM_uint32 *minor_status,
                               gss_ctx_id_t context_handle,
                               int conf_req_flag,
                               gss_qop_t qop_req,
                               OM_uint32 req_output_size,
                               OM_uint32 *max_input_size);

OM_uint32 gssi_wrap_iov(OM_uint32 *minor_status,
                        gss_ctx_id_t context_handle,
                        int conf_req_flag,
                        gss_qop_t qop_req,
                        int *conf_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count);

OM_uint32 gssi_wrap_iov_length(OM_uint32 *minor_status,
                               gss_ctx_id_t context_handle,
                               int conf_req_flag,
                               gss_qop_t qop_req,
                               int *conf_state,
                               gss_iov_buffer_desc *iov,
                               int iov_count);

OM_uint32 gssi_wrap_aead(OM_uint32 *minor_status,
	                 gss_ctx_id_t context_handle,
	                 int conf_req_flag,
	                 gss_qop_t qop_req,
	                 gss_buffer_t input_assoc_buffer,
	                 gss_buffer_t input_payload_buffer,
	                 int *conf_state,
	                 gss_buffer_t output_message_buffer);

OM_uint32 gssi_unwrap(OM_uint32 *minor_status,
                      gss_ctx_id_t context_handle,
                      gss_buffer_t input_message_buffer,
                      gss_buffer_t output_message_buffer,
                      int *conf_state,
                      gss_qop_t *qop_state);

OM_uint32 gssi_unwrap_iov(OM_uint32 *minor_status,
                          gss_ctx_id_t context_handle,
                          int *conf_state,
                          gss_qop_t *qop_state,
                          gss_iov_buffer_desc *iov,
                          int iov_count);

OM_uint32 gssi_unwrap_aead(OM_uint32 *minor_status,
                           gss_ctx_id_t context_handle,
                           gss_buffer_t input_message_buffer,
                           gss_buffer_t input_assoc_buffer,
                           gss_buffer_t output_payload_buffer,
                           int *conf_state,
                           gss_qop_t *qop_state);

OM_uint32 gssi_get_mic(OM_uint32 *minor_status,
                       gss_ctx_id_t context_handle,
                       gss_qop_t qop_req,
                       gss_buffer_t message_buffer,
                       gss_buffer_t message_token);

OM_uint32 gssi_verify_mic(OM_uint32 *minor_status,
                          gss_ctx_id_t context_handle,
                          gss_buffer_t message_buffer,
                          gss_buffer_t message_token,
                          gss_qop_t *qop_state);

OM_uint32 gssi_get_mic_iov(OM_uint32 *minor_status,
                           gss_ctx_id_t context_handle, gss_qop_t qop_req,
                           gss_iov_buffer_desc *iov, int iov_count);

OM_uint32 gssi_get_mic_iov_length(OM_uint32 *minor_status,
                                  gss_ctx_id_t context_handle,
                                  gss_qop_t qop_req, gss_iov_buffer_desc *iov,
                                  int iov_count);

OM_uint32 gssi_verify_mic_iov(OM_uint32 *minor_status,
                              gss_ctx_id_t context_handle,
                              gss_qop_t *qop_state, gss_iov_buffer_desc *iov,
                              int iov_count);

/* misc.c */
OM_uint32 gssi_mech_invoke(OM_uint32 *minor_status,
                           const gss_OID desired_mech,
                           const gss_OID desired_object,
                           gss_buffer_t value);

OM_uint32 gssi_set_neg_mechs(OM_uint32 *minor_status,
                             gss_cred_id_t cred_handle,
                             const gss_OID_set mech_set);

OM_uint32 gssi_complete_auth_token(OM_uint32 *minor_status,
                                   const gss_ctx_id_t context_handle,
                                   gss_buffer_t input_message_buffer);

OM_uint32 gssi_localname(OM_uint32 *minor_status, const gss_name_t name,
                         gss_OID mech_type, gss_buffer_t localname);

OM_uint32 gssi_authorize_localname(OM_uint32 *minor_status,
                                   const gss_name_t name,
                                   gss_buffer_t local_user,
                                   gss_OID local_nametype);

OM_uint32 gssi_map_name_to_any(OM_uint32 *minor_status, gss_name_t name,
                               int authenticated, gss_buffer_t type_id,
                               gss_any_t *output);

OM_uint32 gssi_release_any_name_mapping(OM_uint32 *minor_status,
                                        gss_name_t name,
                                        gss_buffer_t type_id,
                                        gss_any_t *input);
#endif /* _REENTER_GSSI_H */
