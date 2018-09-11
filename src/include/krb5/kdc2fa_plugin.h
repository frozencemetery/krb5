/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/krb5/kdc2fa_plugin.h - KDC second factor plugin interface */
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
 * Declarations for kdc2fa plugin module implementors.
 *
 * The kdc2fa pluggable interface currently only has one supported major
 * version, which is 1.  Major version 1 has a current minor version number of
 * 1.
 *
 * kdc2fa plugin modules should define a function named
 * kdc2fa_<modulename>initvt, matching the signature:
 *
 *   krb5_error_code
 *   kdc2fa_modname_initvt(krb5_context context, int maj_ver, int min_ver,
 *                         krb5_plugin_vtable vtable);
 *
 * The initvt function should:
 *
 * - Check that the supplied maj_ver number is supported by the module, or
 *   return KRB5_PLUGIN_VER_NOTSUPP if it is not.
 *
 * - Cast the vtable pointer as appropriate for maj_ver:
 *     maj_ver == 1: Cast to krb5_kdc2fa_vtable
 *
 * - Initialie the methods of the vtable, stopping as appropriate for the
 *   supplied min_ver.  Optional methods may be left uninitialized.
 *
 * Memory for the vtable is allocated by the caller, not by the module.
 */

#ifndef KRB5_KDC2FA_PLUGIN_H
#define KRB5_KDC2FA_PLUGIN_H

#include <krb5/krb5.h>
#include <krb5/plugin.h>

#include "kdcpreauth_plugin.h"

/* Abstract module datatype. */
typedef struct krb5_kdc2fa_moddata_st *krb5_kdc2fa_moddata;

/* Optional: Initialize module data.  Return 0 on success.  Optionally set
 * *data_out to a module data object to be passed to future calls. */
typedef krb5_error_code
(*krb5_kdc2fa_init_fn)(krb5_context context, krb5_kdc2fa_moddata *data_out);

/* Optional: Release any resources used by module data. */
typedef void
(*krb5_kdc2fa_fini_fn)(krb5_context context, krb5_kdc2fa_moddata data);

/*
 * Responder for krb5_kdc2fa_challenge_fn.  If invoked with a non-zero code,
 * challenge will be ignored and SPAKE will try other kdc2fa modules.  If
 * invoked with a zero code and a NULL challenge, the factor will be present
 * in the SPAKE challenge with no attached data.  challenge will be later
 * passed to free().  req_state contains any serialized state the module
 * wishes to preserve for the lifetime of the request; it will be presented on
 * any challenge() and edata() calls, and eventually passed to free().
 */
typedef void
(*krb5_kdc2fa_challenge_respond_fn)(void *arg, krb5_error_code code,
                                    uint8_t *reqdata, size_t reqdata_len,
                                    uint8_t *challenge, size_t challenge_len);

/*
 * Mandatory: generate a challenge for the specified factor number.  The
 * implementation must invoke respond (passing it the given arg) when
 * complete, successful or not.  The interface is permitted to be
 * asynchronous, using the verto_ctx from cb->event_context().
 *
 * See kdcpreauth_plugin.h for definitions of rock and cb.
 */
typedef void
(*krb5_kdc2fa_challenge_fn)(krb5_context context, krb5_kdc2fa_moddata data,
                            krb5_kdcpreauth_callbacks cb,
                            krb5_kdcpreauth_rock rock, int32_t spake_number,
                            krb5_kdc2fa_challenge_respond_fn respond,
                            void *arg);

/*
 * Responder for krb5_kdc2fa_verify_fn.  Invoke with code 0 to indicate
 * successful verification of the respone; any other code indicates failure,
 * and terminates the request.  If another challenge is provided, it will
 * generate an encdata request.  The module may preserve serialized request
 * state in req_state; it will be presented on any verify() calls, and
 * eventually passed to free().
 */
typedef void
(*krb5_kdc2fa_verify_respond_fn)(void *arg, krb5_error_code code,
                                 uint8_t *reqdata, size_t reqdata_len,
                                 uint8_t *challenge, size_t challenge_len);

/*
 * Mandatory: verify a client response to a previously generated challenge or
 * encdata for the specified second factor.  The implementation must invoke
 * respond (passing it the given arg) when complete, successful or not.  The
 * interface is permitted to be asynchronous, using the verto_ctx from
 * cb->event_context().  Implementations may also register auth_indicators
 * using cb->add_auth_indicator().  The module must not free reqdata.
 *
 * See kdcpreauth_plugin.h for definitions of rock and cb.
 */
typedef void
(*krb5_kdc2fa_verify_fn)(krb5_context context, krb5_kdc2fa_moddata data,
                         uint8_t *reqdata, size_t reqdata_len,
                         krb5_kdcpreauth_callbacks cb,
                         krb5_kdcpreauth_rock rock, int32_t spake_number,
                         uint8_t *response_data, size_t response_len,
                         krb5_kdc2fa_verify_respond_fn respond, void *arg);

/* kdc2fa vtable for major version 1. */
typedef struct krb5_kdc2fa_vtable_st {
    const char *name; /* Mandatory: name of module. */

    /* Mandatory:  SPAKE second factor type supported by this module. */
    int32_t factor;

    krb5_kdc2fa_init_fn init; /* Optional */
    krb5_kdc2fa_fini_fn fini; /* Optional */

    krb5_kdc2fa_challenge_fn challenge; /* Mandatory */
    krb5_kdc2fa_verify_fn verify; /* Mandatory */

    /* Minor version 1 ends here. */
} *krb5_kdc2fa_vtable;

#endif /* KDC2FA_PLUGIN_H */
