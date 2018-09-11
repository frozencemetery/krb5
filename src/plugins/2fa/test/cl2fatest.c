/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/2fa/test/cl2fatest.c - Test cl2fa module */
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
#include <krb5/cl2fa_plugin.h>

#define TEST_2FA_FACTOR -87

static krb5_error_code
increment(int32_t spake_number, const uint8_t *challenge,
          size_t challenge_len, uint8_t **response_out,
          size_t *response_len_out)
{
    krb5_error_code ret;
    uint8_t *response = NULL;
    size_t response_len = 0;

    if (spake_number != TEST_2FA_FACTOR) {
        ret = KRB5_PLUGIN_NO_HANDLE;
        goto done;
    } else if (challenge_len != 1) {
        ret = EINVAL;
        goto done;
    }

    response = k5calloc(1, sizeof(*response), &ret);
    if (response == NULL)
        goto done;

    response[0] = challenge[0] + 1;
    response_len = 1;

done:
    *response_out = response;
    *response_len_out = response_len;
    return ret;
}

static krb5_error_code
cltest_respond(krb5_context context, krb5_cl2fa_moddata moddata,
               krb5_cl2fa_reqdata *reqdata, krb5_clpreauth_callbacks cb,
               krb5_clpreauth_rock rock, int32_t spake_number,
               const char *realm, const uint8_t *challenge,
               size_t challenge_len, uint8_t **response_out,
               size_t *response_len_out)
{
    return increment(spake_number, challenge, challenge_len, response_out,
                     response_len_out);
}

static krb5_error_code
cltest_encdata(krb5_context context, krb5_cl2fa_moddata moddata,
               krb5_cl2fa_reqdata reqdata, krb5_clpreauth_callbacks cb,
               krb5_clpreauth_rock rock, int32_t spake_number,
               const char *realm, const uint8_t *challenge,
               size_t challenge_len, uint8_t **response_out,
               size_t *response_len_out)
{
    return increment(spake_number, challenge, challenge_len, response_out,
                     response_len_out);
}

krb5_error_code
cl2fa_test_initvt(krb5_context context, int maj_ver, int min_ver,
                  krb5_plugin_vtable vtable);
krb5_error_code
cl2fa_test_initvt(krb5_context context, int maj_ver, int min_ver,
                  krb5_plugin_vtable vtable)
{
    krb5_cl2fa_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_cl2fa_vtable)vtable;
    vt->name = "test";
    vt->factor = TEST_2FA_FACTOR;
    vt->init = NULL;
    vt->fini = NULL;
    vt->request_fini = NULL;
    vt->respond = cltest_respond;
    vt->encdata = cltest_encdata;
}
