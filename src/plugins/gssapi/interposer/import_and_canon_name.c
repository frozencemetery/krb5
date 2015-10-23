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

OM_uint32 gssi_display_name(OM_uint32 *minor_status,
                            gss_name_t input_name,
                            gss_buffer_t output_name_buffer,
                            gss_OID *output_name_type)
{
    GSSI_TRACE();

    output_name_buffer->length = 0;
    output_name_buffer->value = NULL;
    if (output_name_type)
        *output_name_type = GSS_C_NO_OID;

    return gss_display_name(minor_status, input_name, output_name_buffer,
                            output_name_type);
}

OM_uint32 gssi_display_name_ext(OM_uint32 *minor_status,
                                gss_name_t input_name,
                                gss_OID display_as_name_type,
                                gss_buffer_t display_name)
{
    GSSI_TRACE();
    return gss_display_name_ext(minor_status, input_name,
                                display_as_name_type, display_name);
}

OM_uint32 gssi_import_name_by_mech(OM_uint32 *minor_status,
                                   gss_OID mech_type,
                                   gss_buffer_t input_name_buffer,
                                   gss_OID input_name_type,
                                   gss_name_t *output_name)
{
    gss_buffer_desc wrap_token;
    OM_uint32 major;
    uint16_t be_len16;
    uint32_t be_len32;
    char *tokbuf;
    size_t i;

    GSSI_TRACE();

    wrap_token.length = 2 + sizeof(uint16_t) + 1 +
        sizeof(uint8_t) + mech_type->length +
        sizeof(uint32_t) + input_name_buffer->length; 
    tokbuf = malloc(wrap_token.length);
    if (!tokbuf) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    wrap_token.value = tokbuf;
    i = 0;

    tokbuf[i++] = 0x04;
    tokbuf[i++] = 0x01;

    be_len16 = htobe16(mech_type->length + 2);
    memcpy(tokbuf + i, &be_len16, sizeof(uint16_t));
    i += sizeof(uint16_t);

    tokbuf[i++] = 0x06;

    tokbuf[i++] = (uint8_t)(mech_type->length);

    memcpy(tokbuf + i, mech_type->elements, mech_type->length);
    i += mech_type->length;

    be_len32 = htobe32(input_name_buffer->length);
    memcpy(tokbuf + i, &be_len32, sizeof(uint32_t));
    i += sizeof(uint32_t);

    memcpy(tokbuf + i, input_name_buffer->value, input_name_buffer->length);
    i += input_name_buffer->length;

    if (i != wrap_token.length) {
        fprintf(stderr, "RHARWOOD YOU BLOKE IT\n");
        exit(1);
    }
    
    major = gss_import_name(minor_status,
                            &wrap_token,
                            GSS_C_NT_EXPORT_NAME,
                            output_name);
    free(wrap_token.value);
    return major;
}

OM_uint32 gssi_export_name(OM_uint32 *minor_status,
                           const gss_name_t input_name,
                           gss_buffer_t exported_name)
{
    GSSI_TRACE();
    return gss_export_name(minor_status, input_name, exported_name);
}

OM_uint32 gssi_export_name_composite(OM_uint32 *minor_status,
                                     const gss_name_t input_name,
                                     gss_buffer_t exported_composite_name)
{
    GSSI_TRACE();
    return gss_export_name_composite(minor_status, input_name,
                                     exported_composite_name);
}

OM_uint32 gssi_duplicate_name(OM_uint32 *minor_status,
                              const gss_name_t input_name,
                              gss_name_t *dest_name)
{
    GSSI_TRACE();
    return gss_duplicate_name(minor_status, input_name, dest_name);
}

OM_uint32 gssi_inquire_name(OM_uint32 *minor_status,
                            gss_name_t input_name,
                            int *name_is_NM,
                            gss_OID *NM_mech,
                            gss_buffer_set_t *attrs)
{
    GSSI_TRACE();
    return gss_inquire_name(minor_status, input_name, name_is_NM, NM_mech,
                            attrs);
}

OM_uint32 gssi_release_name(OM_uint32 *minor_status,
                            gss_name_t *input_name)
{
    GSSI_TRACE();
    return gss_release_name(minor_status, input_name);
}

OM_uint32 gssi_compare_name(OM_uint32 *minor_status,
                            gss_name_t name1,
                            gss_name_t name2,
                            int *name_equal)
{
    GSSI_TRACE();
    return gss_compare_name(minor_status, name1, name2, name_equal);
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
    GSSI_TRACE();
    return gss_get_name_attribute(minor_status, input_name, attr,
                                  authenticated, complete, value,
                                  display_value, more);
}

OM_uint32 gssi_set_name_attribute(OM_uint32 *minor_status,
                                  gss_name_t input_name,
                                  int complete,
                                  gss_buffer_t attr,
                                  gss_buffer_t value)
{
    GSSI_TRACE();
    return gss_set_name_attribute(minor_status, input_name,
                                  complete, attr, value);
}

OM_uint32 gssi_delete_name_attribute(OM_uint32 *minor_status,
                                     gss_name_t input_name,
                                     gss_buffer_t attr)
{
    GSSI_TRACE();
    return gss_delete_name_attribute(minor_status, input_name, attr);
}
