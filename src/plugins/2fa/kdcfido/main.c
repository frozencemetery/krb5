/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/2fa/kdcfido/main.c - FIDO kdc2fa module */
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

#include "k5-int.h"
#include <errno.h>
#include <fido.h>
#include <fido/err.h>
#include <krb5/kdc2fa_plugin.h>

#define FIDO_CHALLENGE_LEN 32
#define FIDO_SPAKE_NUM -1

static void
fido_log(krb5_context ctx, int code, krb5_error_code *ret)
{
    /*
     * The library works by building a context and then only actually talking
     * to the token at make_cred or verify_cred time.  So its only reportable
     * failure is "the token rejected the request, unless we typo a call.
     */
    *ret = EINVAL;
    TRACE(ctx, "kdcfido error: {str} ({int})", fido_strerr(code), code);
}

static krb5_error_code
kdcfido_init(krb5_context context, krb5_kdc2fa_moddata *data_out)
{
    fido_init(0);
    return 0;
}

static void
kdcfido_challenge(krb5_context context, krb5_kdc2fa_moddata data,
                  krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
                  int32_t spake_number,
                  krb5_kdc2fa_challenge_respond_fn respond, void *arg)
{
    krb5_error_code kret;
    unsigned char *challenge;
    krb5_data d;

    if (spake_number != FIDO_SPAKE_NUM) {
        (*respond)(arg, KRB5_PLUGIN_NO_HANDLE, NULL, 0, NULL, 0);
        return;
    }
    challenge = k5alloc(FIDO_CHALLENGE_LEN + 1, &kret);
    if (challenge == NULL) {
        (*respond)(arg, kret, NULL, 0, NULL, 0);
        return;
    }

    d.data = (void *)challenge;
    d.length = FIDO_CHALLENGE_LEN;
    kret = krb5_c_random_make_octets(context, &d);
    if (kret != 0) {
        (*respond)(arg, kret, NULL, 0, NULL, 0);
        return;
    }
    challenge[FIDO_CHALLENGE_LEN] = '\0';

    (*respond)(arg, 0, challenge, FIDO_CHALLENGE_LEN, challenge,
               FIDO_CHALLENGE_LEN);
}

/* Wire format: format | authdata | signature | certificate.  Each field is
 * preceded by 4 big endian length bytes. */
static krb5_error_code
decode(krb5_data *response, krb5_data *fmt, krb5_data *cert,
       krb5_data *authdata, krb5_data *sig)
{
    size_t offset = 0;
    char *d = response->data;

    if (offset + 4 > response->length)
        return KRB5_PARSE_MALFORMED;
    fmt->length = load_32_be(d + offset);
    offset += 4;
    if (offset + fmt->length > response->length)
        return KRB5_PARSE_MALFORMED;
    offset += fmt->length;

    if (offset + 4 > response->length)
        return KRB5_PARSE_MALFORMED;
    authdata->length = load_32_be(d + offset);
    offset += 4;
    if (offset + authdata->length > response->length)
        return KRB5_PARSE_MALFORMED;
    offset += authdata->length;

    if (offset + 4 > response->length)
        return KRB5_PARSE_MALFORMED;
    sig->length = load_32_be(d + offset);
    offset += 4;
    if (offset + sig->length > response->length)
        return KRB5_PARSE_MALFORMED;
    offset += sig->length;

    if (offset + 4 > response->length)
        return KRB5_PARSE_MALFORMED;
    cert->length = load_32_be(d + offset);
    offset += 4;
    if (offset + cert->length != response->length)
        return KRB5_PARSE_MALFORMED;

    fmt->data = d + 4;
    authdata->data = fmt->data + fmt->length + 4;
    sig->data = authdata->data + authdata->length + 4;
    cert->data = sig->data + sig->length + 4;

    fmt->data[fmt->length] = '\0';
    authdata->data[authdata->length] = '\0';
    sig->data[sig->length] = '\0';

    return 0;
}

static void
kdcfido_verify(krb5_context context, krb5_kdc2fa_moddata data,
               uint8_t *reqdata, size_t reqdata_len,
               krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
               int32_t spake_number, uint8_t *response_data,
               size_t response_len, krb5_kdc2fa_verify_respond_fn respond,
               void *arg)
{
    fido_cred_t *cred = NULL;
    int fret;
    krb5_error_code kret;
    krb5_principal client;
    char *realm;
    krb5_data cert = empty_data(), authdata = empty_data(),
        sig = empty_data(), fmt = empty_data();
    krb5_data response = make_data(response_data, response_len);

    if (spake_number != FIDO_SPAKE_NUM) {
        (*respond)(arg, KRB5_PLUGIN_NO_HANDLE, NULL, 0, NULL, 0);
        return;
    } else if (reqdata_len != FIDO_CHALLENGE_LEN) {
        (*respond)(arg, EINVAL, NULL, 0, NULL, 0);
        return;
    }

    cred = fido_cred_new();
    if (cred == NULL) {
        (*respond)(arg, ENOMEM, NULL, 0, NULL, 0);
        return;
    }

    fret = fido_cred_set_clientdata_hash(cred, reqdata, FIDO_CHALLENGE_LEN);
    if (fret != FIDO_OK)
        goto fido_error;

    /* This call is mandatory, and not all tokens support RS256. */
    fret = fido_cred_set_type(cred, COSE_ES256);
    if (fret != FIDO_OK)
        goto fido_error;

    /* Requires callbacks version 4 (already present at the time). */
    client = cb->client_name(context, rock);
    realm = client->realm.data;
    fret = fido_cred_set_rp(cred, realm, realm);
    if (fret != FIDO_OK)
        goto fido_error;

    kret = decode(&response, &fmt, &cert, &authdata, &sig);
    if (kret != 0)
        goto krb_done;

    fret = fido_cred_set_fmt(cred, fmt.data);
    if (fret != FIDO_OK)
        goto fido_error;

    fret = fido_cred_set_authdata(cred, (unsigned char *)authdata.data,
                                 authdata.length);
    if (fret != FIDO_OK)
        goto fido_error;

    fret = fido_cred_set_sig(cred, (unsigned char *)sig.data, sig.length);
    if (fret != FIDO_OK)
        goto fido_error;

    /*
     * A problem that needs to be addressed in order for this plugin to
     * *actually* go in-tree is what to do about the certificate.  We need
     * some form of enrollment, which means associating more state with a
     * principal, as well as a means to perform such enrollment.
     *
     * This is very doable in something like freeIPA, where the web interface
     * or CLI can have interfaces for registration.  That doesn't help
     * standalone krb5 much, though.
     *
     * On the other hand, the client is actually fine as-is - it doesn't need
     * to be aware of whether its certificate has been enrolled.  One could
     * even imagine a Trust-On-First-Use scenario with these where it might
     * actually be desirable for it to not know.
     *
     * To be determined, I guess.
     */
    fret = fido_cred_set_x509(cred, (unsigned char *)cert.data, cert.length);
    if (fret != FIDO_OK)
        goto fido_error;

    fret = fido_cred_verify(cred);
    if (fret != FIDO_OK) {
        fido_log(context, fret, &kret);
        kret = KRB5KDC_ERR_PREAUTH_FAILED;
        goto krb_done;
    }

    goto krb_done;

fido_error:
    fido_log(context, fret, &kret);
krb_done:
    fido_cred_free(&cred);
    (*respond)(arg, kret, NULL, 0, NULL, 0);
}

krb5_error_code
kdc2fa_kdcfido_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable);

krb5_error_code
kdc2fa_kdcfido_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable)
{
    krb5_kdc2fa_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdc2fa_vtable)vtable;
    vt->name = "kdcfido";
    vt->factor = FIDO_SPAKE_NUM;
    vt->init = kdcfido_init;
    vt->fini = NULL;
    vt->challenge = kdcfido_challenge;
    vt->verify = kdcfido_verify;
    return 0;
}
