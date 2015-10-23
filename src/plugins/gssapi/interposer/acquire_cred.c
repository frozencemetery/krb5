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

OM_uint32 gssi_acquire_cred(OM_uint32 *minor_status,
                            const gss_name_t desired_name,
                            OM_uint32 time_req,
                            const gss_OID_set desired_mechs,
                            gss_cred_usage_t cred_usage,
                            gss_cred_id_t *output_cred_handle,
                            gss_OID_set *actual_mechs,
                            OM_uint32 *time_rec)
{
    GSSI_TRACE();
    return gssi_acquire_cred_from(minor_status, desired_name, time_req,
                                  desired_mechs, cred_usage, NULL,
                                  output_cred_handle, actual_mechs, time_rec);
}

OM_uint32 gssi_acquire_cred_from(OM_uint32 *minor_status,
                                 const gss_name_t desired_name,
                                 OM_uint32 time_req,
                                 const gss_OID_set desired_mechs,
                                 gss_cred_usage_t cred_usage,
                                 gss_const_key_value_set_t cred_store,
                                 gss_cred_id_t *output_cred_handle,
                                 gss_OID_set *actual_mechs,
                                 OM_uint32 *time_rec)
{
    OM_uint32 major, minor;
    gss_OID_set special_mechs;

    GSSI_TRACE();

    special_mechs = re_special_mechs(desired_mechs);
    if (special_mechs == GSS_C_NO_OID_SET) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    }

    major = gss_acquire_cred_from(minor_status, desired_name, time_req,
                                  special_mechs,
                                  cred_usage, cred_store, output_cred_handle,
                                  actual_mechs, time_rec);
    gss_release_oid_set(&minor, &special_mechs);
    return major;
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
    OM_uint32 major, minor;
    gss_OID_set special_mechs;

    GSSI_TRACE();

    special_mechs = re_special_mechs(desired_mechs);
    if (special_mechs == GSS_C_NO_OID_SET) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    }

    major = gss_acquire_cred_with_password(minor_status, desired_name,
                                           password, time_req,
                                           special_mechs,
                                           cred_usage, output_cred_handle,
                                           actual_mechs, time_rec);    
    gss_release_oid_set(&minor, &special_mechs);
    return major;
}

OM_uint32 gssi_acquire_cred_impersonate_name(OM_uint32 *minor_status,
                                             gss_cred_id_t imp_cred_handle,
                                             const gss_name_t desired_name,
                                             OM_uint32 time_req,
                                             const gss_OID_set desired_mechs,
                                             gss_cred_usage_t cred_usage,
                                             gss_cred_id_t *output_cred_handle,
                                             gss_OID_set *actual_mechs,
                                             OM_uint32 *time_rec)
{
    OM_uint32 major, minor;
    gss_OID_set special_mechs;

    GSSI_TRACE();

    special_mechs = re_special_mechs(desired_mechs);
    if (special_mechs == GSS_C_NO_OID_SET) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    }

    major = gss_acquire_cred_impersonate_name(minor_status, imp_cred_handle,
                                              desired_name, time_req,
                                              special_mechs,
                                              cred_usage, output_cred_handle,
                                              actual_mechs, time_rec);
    gss_release_oid_set(&minor, &special_mechs);
    return major;
}
