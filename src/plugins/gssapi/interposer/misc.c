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

OM_uint32 gssi_mech_invoke(OM_uint32 *minor_status,
                           const gss_OID desired_mech,
                           const gss_OID desired_object,
                           gss_buffer_t value)
{
    GSSI_TRACE();
    return gssspi_mech_invoke(minor_status,
                              re_special_mech(desired_mech),
                              desired_object, value);
}

OM_uint32 gssi_set_neg_mechs(OM_uint32 *minor_status,
                             gss_cred_id_t cred_handle,
                             const gss_OID_set mech_set)
{
    GSSI_TRACE();
    return gss_set_neg_mechs(minor_status, cred_handle,
                             re_special_mechs(mech_set));
}

OM_uint32 gssi_complete_auth_token(OM_uint32 *minor_status,
                                   const gss_ctx_id_t context_handle,
                                   gss_buffer_t input_message_buffer)
{
    GSSI_TRACE();
    return gss_complete_auth_token(minor_status, context_handle,
                                   input_message_buffer);
}

OM_uint32 gssi_localname(OM_uint32 *minor_status, const gss_name_t name,
                         gss_OID mech_type, gss_buffer_t localname)
{
    GSSI_TRACE();
    return gss_localname(minor_status, name,
                         re_special_mech(mech_type),
                         localname);
}

OM_uint32 gssi_authorize_localname(OM_uint32 *minor_status,
                                   const gss_name_t name,
                                   gss_buffer_t local_user,
                                   gss_OID local_nametype)
{
    OM_uint32 major, minor;
    gss_name_t username;

    GSSI_TRACE();

    if (name == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ;

    major = gss_import_name(&minor, local_user, local_nametype, &username);
    if (major != GSS_S_COMPLETE) {
        *minor_status = minor;
        return major;
    }

    major = gss_authorize_localname(minor_status, name, username);
    gss_release_name(&minor, &username);
    return major;
}

OM_uint32 gssi_map_name_to_any(OM_uint32 *minor_status, gss_name_t name,
                               int authenticated, gss_buffer_t type_id,
                               gss_any_t *output)
{
    GSSI_TRACE();
    return gss_map_name_to_any(minor_status, name, authenticated, type_id,
                               output);
}

OM_uint32 gssi_release_any_name_mapping(OM_uint32 *minor_status,
                                        gss_name_t name,
                                        gss_buffer_t type_id,
                                        gss_any_t *input)
{
    GSSI_TRACE();
    return gss_release_any_name_mapping(minor_status, name, type_id, input);
}

