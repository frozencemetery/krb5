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

OM_uint32 gssi_inquire_names_for_mech(OM_uint32 *minor_status,
                                      gss_OID mech_type,
                                      gss_OID_set *mech_names)
{
    GSSI_TRACE();
    return gss_inquire_names_for_mech(minor_status,
                                      re_special_mech(mech_type),
                                      mech_names);
}

OM_uint32 gssi_inquire_attrs_for_mech(OM_uint32 *minor_status,
                                      gss_OID mech,
                                      gss_OID_set *mech_attrs,
                                      gss_OID_set *known_mech_attrs)
{
    GSSI_TRACE();
    return gss_inquire_attrs_for_mech(minor_status,
                                      re_special_mech(mech),
                                      mech_attrs, known_mech_attrs);
}

OM_uint32 gssi_inquire_saslname_for_mech(OM_uint32 *minor_status,
                                         const gss_OID desired_mech,
                                         gss_buffer_t sasl_mech_name,
                                         gss_buffer_t mech_name,
                                         gss_buffer_t mech_description)
{
    GSSI_TRACE();
    return gss_inquire_saslname_for_mech(minor_status,
                                         re_special_mech(desired_mech),
                                         sasl_mech_name, mech_name,
                                         mech_description);
}
