/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/2fa/clfido/main.c - FIDO cl2fa module */
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
#include <krb5/cl2fa_plugin.h>

/* 
 * Only support one token being present in the system.  It's not clear what
 * support for multiple tokens could even look like: SPAKE only allows one
 * response per challenge anyway.
 */
#define FIDO_MAX_DEVS 1
#define FIDO_SPAKE_NUM -1
#define FIDO_CHALLENGE_LEN 32

static void
fido_log(krb5_context ctx, int code)
{
    /*
     * The library works by building a context and then only actually talking
     * to the token at make_cred or verify_cred time.  So its only reportable
     * failure is "the token rejected the request", unless we typo a call.
     */
    TRACE(ctx, "clfido error: {str} ({int})", fido_strerr(code), code);
}

/* libfido2 creds don't seem to be reusable, and tokens are hotpluggable, so
 * there's little point in keeping state. */
static krb5_error_code
clfido_init(krb5_context context, krb5_cl2fa_moddata *moddata_out)
{
    fido_init(0);
    return 0;
}

static fido_dev_t *
get_dev(krb5_context ctx) {
    fido_dev_info_t *devlist = NULL;
    size_t num_devices = 0;
    fido_dev_t *dev = NULL;
    const fido_dev_info_t *di;
    const char *path;
    int fret = 0;

    devlist = fido_dev_info_new(FIDO_MAX_DEVS);
    if (devlist == NULL)
        goto done;

    fret = fido_dev_info_manifest(devlist, FIDO_MAX_DEVS, &num_devices);
    if (fret != FIDO_OK || num_devices == 0) {
        TRACE(ctx, "clfido error: No U2F devices found!\n");
        goto done;
    }

    di = fido_dev_info_ptr(devlist, 0);
    path = fido_dev_info_path(di);

    dev = fido_dev_new();
    if (dev == NULL)
        goto done;

    fret = fido_dev_open(dev, path);

done:
    if (fret != FIDO_OK) {
        fido_log(ctx, fret);
        if (dev != NULL)
            fido_dev_close(dev);
        fido_dev_free(&dev);
    }
    fido_dev_info_free(&devlist, num_devices);
    return dev;
}

/* Wire format: format | authdata | signature | certificate.  Each field is
 * preceded by 4 big endian length bytes. */
static void
pack(const char *fmt, const unsigned char *authdata, size_t authdata_len,
     const unsigned char *sig, size_t sig_len, const unsigned char *cert,
     size_t cert_len, uint8_t **payload_out, size_t *payload_len_out)
{
    size_t payload_len, fmt_len;
    uint8_t *payload = NULL;
    size_t i = 0;

    fmt_len = strlen(fmt);

    payload_len = 4 * 4 + fmt_len + authdata_len + sig_len + cert_len;
    payload = malloc(payload_len);
    if (payload == NULL)
        return;

    store_32_be(fmt_len, payload + i);
    i += 4;
    memcpy(payload + i, fmt, fmt_len);
    i += fmt_len;

    store_32_be(authdata_len, payload + i);
    i += 4;
    memcpy(payload + i, authdata, authdata_len);
    i += authdata_len;

    store_32_be(sig_len, payload + i);
    i += 4;
    memcpy(payload + i, sig, sig_len);
    i += sig_len;

    store_32_be(cert_len, payload + i);
    i += 4;
    memcpy(payload + i, cert, cert_len);
    i += cert_len;

    assert(i == payload_len);

    *payload_out = payload;
    *payload_len_out = payload_len;
}

static krb5_error_code
clfido_respond(krb5_context context, krb5_cl2fa_moddata modddata,
               krb5_cl2fa_reqdata *reqdata, krb5_clpreauth_callbacks cb,
               krb5_clpreauth_rock rock, int32_t spake_number,
               const char *realm, const uint8_t *challenge,
               size_t challenge_len, uint8_t **response_out,
               size_t *response_len_out)
{
    krb5_error_code ret = 0;
    int fret = FIDO_OK;
    fido_cred_t *cred = NULL;
    fido_dev_t *dev = NULL;
    uint8_t *response = NULL;
    size_t response_len;

    if (spake_number != FIDO_SPAKE_NUM)
        return KRB5_PLUGIN_NO_HANDLE;
    else if (challenge_len != FIDO_CHALLENGE_LEN) {
        TRACE(context, "clfido error: invalid challenge length\n");
        return EINVAL;
    }

    *response_out = NULL;
    *response_len_out = 0;

    cred = fido_cred_new();
    if (cred == NULL)
        return ENOMEM;

    /* Setting this is mandatory, and not all tokens support RS256. */
    fret = fido_cred_set_type(cred, COSE_ES256);
    if (fret != FIDO_OK)
        goto done;
    
    fret = fido_cred_set_clientdata_hash(cred, challenge, challenge_len);
    if (fret != FIDO_OK)
        goto done;

    fret = fido_cred_set_rp(cred, realm, realm);
    if (fret != FIDO_OK)
        goto done;

    dev = get_dev(context);
    if (dev == NULL) { /* No device present */
        ret = KRB5_PLUGIN_NO_HANDLE;
        goto done;
    }

    fret = fido_dev_make_cred(dev, cred, NULL);
    if (fret != FIDO_OK)
        goto done;

    pack(fido_cred_fmt(cred), fido_cred_authdata_ptr(cred),
         fido_cred_authdata_len(cred), fido_cred_sig_ptr(cred),
         fido_cred_sig_len(cred), fido_cred_x5c_ptr(cred),
         fido_cred_x5c_len(cred), &response, &response_len);
    if (response == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *response_out = response;
    *response_len_out = response_len;
done:
    if (ret == 0 && fret != FIDO_OK) {
        fido_log(context, fret);
        ret = EINVAL;
    }
    if (dev != NULL)
        fido_dev_close(dev);
    fido_dev_free(&dev);
    fido_cred_free(&cred);
    return ret;
}

krb5_error_code
cl2fa_clfido_initvt(krb5_context context, int maj_ver, int min_ver,
                    krb5_plugin_vtable vtable);

krb5_error_code
cl2fa_clfido_initvt(krb5_context context, int maj_ver, int min_ver,
                    krb5_plugin_vtable vtable)
{
    krb5_cl2fa_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_cl2fa_vtable)vtable;
    vt->name = "clfido";
    vt->factor = FIDO_SPAKE_NUM;
    vt->init = clfido_init;
    vt->fini = NULL;
    vt->request_fini = NULL;
    vt->respond = clfido_respond;
    vt->encdata = NULL;
    return 0;
}
