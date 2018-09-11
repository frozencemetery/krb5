/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/2fa/test/kdc2fatest.c - Test kdc2fa module */
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
#include <krb5/kdc2fa_plugin.h>

#define TEST_2FA_FACTOR -87

static void
kdctest_challenge(krb5_context context, krb5_kdc2fa_moddata moddata,
                  krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
                  int32_t spake_number,
                  krb5_kdc2fa_challenge_respond_fn respond, void *arg)
{
    krb5_error_code ret = 0;
    uint8_t *chal = NULL, *reqdata = NULL;
    size_t chal_len = 0, reqdata_len = 0;

    if (spake_number != TEST_2FA_FACTOR) {
        ret = KRB5_PLUGIN_NO_HANDLE;
        goto done;
    }

    chal = k5calloc(2, sizeof(*chal), &ret);
    if (chal == NULL)
        goto done;

    reqdata = k5calloc(2, sizeof(*reqdata), &ret);
    if (reqdata == NULL) {
        free(chal);
        chal = NULL;
        goto done;
    }

    chal[0] = reqdata[0] = 1;
    chal_len = reqdata_len = 1;

done:
    (*respond)(arg, ret, chal, chal_len, reqdata, reqdata_len);
}

static void
kdctest_verify(krb5_context context, krb5_kdc2fa_moddata moddata,
               uint8_t *reqdata, size_t reqdata_len,
               krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
               int32_t spake_number, uint8_t *response_data,
               size_t response_len, krb5_kdc2fa_verify_respond_fn respond,
               void *arg)
{
    krb5_error_code ret = 0;
    uint8_t *reply = NULL, *newreqdata = NULL;
    size_t reply_len = 0, newreqdata_len = 0;

    if (spake_number != TEST_2FA_FACTOR) {
        ret = KRB5_PLUGIN_NO_HANDLE;
        goto done;
    } else if (reqdata_len != 1 || response_len != 1) {
        ret = EINVAL;
        goto done;
    } else if (reqdata[0] + 1 != response_data[0]) {
        ret = KRB5KDC_ERR_PREAUTH_FAILED;
        goto done;
    } else if (response_data[0] == 2) {
        /* Complete */
        cb->add_auth_indicator(context, rock, "ind2fatest");
        goto done;
    }
    
    reply = k5calloc(1, sizeof(*reply), &ret);
    if (reply == NULL)
        goto done;
    newreqdata = k5calloc(1, sizeof(*newreqdata), &ret);
    if (newreqdata == NULL) {
        free(reply);
        reply = NULL;
        goto done;
    }

    reply[0] = newreqdata[0] = response_data[0] + 1;
    reply_len = newreqdata_len = 1;
    ret = KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED;
done:
    (*respond)(arg, ret, reply, reply_len, newreqdata, newreqdata_len);
}

krb5_error_code
kdc2fa_test_initvt(krb5_context context, int maj_ver, int min_ver,
                   krb5_plugin_vtable vtable);
krb5_error_code
kdc2fa_test_initvt(krb5_context context, int maj_ver, int min_ver,
                   krb5_plugin_vtable vtable)
{
    krb5_kdc2fa_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdc2fa_vtable)vtable;
    vt->name = "test";
    vt->factor = TEST_2FA_FACTOR;
    vt->init = NULL;
    vt->fini = NULL;
    vt->challenge = kdctest_challenge;
    vt->verify = kdctest_verify;
    return 0;
}
