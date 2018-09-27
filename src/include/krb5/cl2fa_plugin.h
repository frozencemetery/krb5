/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/krb5/clfa_plugin.h - client second factor plugin interface */
/*
 * Copyright (C) 2018 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Declarations for cl2fa plugin module implementors.
 *
 * The cl2fa interface has a single supported major version, which is
 * 1.  Major version 1 has a current minor version of 2.  cl2fa modules
 * should define a function named cl2fa_<modulename>_initvt, matching
 * the signature:
 *
 *   krb5_error_code
 *   cl2fa_modname_initvt(krb5_context context, int maj_ver,
 *                        int min_ver, krb5_plugin_vtable vtable);
 * The initvt function should:
 *
 * - Check that the supplied maj_ver number is supported by the module, or
 *   return KRB5_PLUGIN_VER_NOTSUPP if it is not.
 *
 * - Cast the vtable pointer as appropriate for the interface and maj_ver:
 *     maj_ver == 1: Cast to krb5_cl2fa_vtable
 *
 * - Initialize the methods of the vtable, stopping as appropriate for the
 *   supplied min_ver.  Optional methods may be left uninitialized.
 *
 * Memory for the vtable is allocated by the caller, not by the module.
 */

#ifndef KRB5_CL2FA_PLUGIN_H
#define KRB5_CL2FA_PLUGIN_H

#include <krb5/krb5.h>
#include <krb5/plugin.h>
#include <krb5/clpreauth_plugin.h>

/* Abstract module datatypes. */
typedef struct krb5_cl2fa_moddata_st *krb5_cl2fa_moddata;
typedef struct krb5_cl2fa_reqdata_st *krb5_cl2fa_reqdata;

/* Optional: Initialize module data.  Return 0 on success.  Optionally set
 * *moddata_out to a module data object to be passed to future calls. */
typedef krb5_error_code
(*krb5_cl2fa_init_fn)(krb5_context context, krb5_cl2fa_moddata *moddata_out);

/* Optional: Release any resources used by moddata. */
typedef void
(*krb5_cl2fa_fini_fn)(krb5_context context, krb5_cl2fa_moddata moddata);

/* Optional: Release any resources used by reqdata. */
typedef void
(*krb5_cl2fa_request_fini_fn)(krb5_context context,
                              krb5_cl2fa_reqdata reqdata);

/*
 * Mandatory: respond to the challenge for the associated SPAKE number.
 * Non-zero return indicates inability to respond; the client will try other
 * cl2fa modules.  On success, this factor will be used, and the response will
 * be sent to the KDC.  reqdata will be presented to all subsequent encdata()
 * calls.
 *
 * For definitions of cb and rock, see clpreauth_plugin.h.
 */
typedef krb5_error_code
(*krb5_cl2fa_responder_fn)(krb5_context context, krb5_cl2fa_moddata moddata,
                           krb5_cl2fa_reqdata *reqdata,
                           krb5_clpreauth_callbacks cb,
                           krb5_clpreauth_rock rock, int32_t spake_number,
                           const char *realm, const uint8_t *challenge,
                           size_t challenge_len, uint8_t **response_out,
                           size_t *response_len_out);

/*
 * Optional: respond to the encdata message for the associated SPAKE number.
 * Non-zero return indicates failure.
 *
 * For definitions of cb and rock, see clpreauth_plugin.h.
 */
typedef krb5_error_code
(*krb5_cl2fa_encdata_fn)(krb5_context context, krb5_cl2fa_moddata moddata,
                         krb5_cl2fa_reqdata reqdata,
                         krb5_clpreauth_callbacks cb,
                         krb5_clpreauth_rock rock, int32_t spake_number,
                         const char *realm, const uint8_t *challenge,
                         size_t challenge_len, uint8_t **response_out,
                         size_t *response_len_out);

typedef struct krb5_cl2fa_vtable_st {
    const char *name; /* Mandatory: name of module. */

    /* Mandatory: SPAKE second factor type supported by this module. */
    int32_t factor;

    krb5_cl2fa_init_fn init; /* Optional */
    krb5_cl2fa_fini_fn fini; /* Optional */
    krb5_cl2fa_request_fini_fn request_fini; /* Optional */

    krb5_cl2fa_responder_fn respond; /* Mandatory */
    krb5_cl2fa_encdata_fn encdata; /* Optional */
    /* Minor version 1 ends here. */
} *krb5_cl2fa_vtable;

#endif
