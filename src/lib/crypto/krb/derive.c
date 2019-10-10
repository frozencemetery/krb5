/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "crypto_int.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

static krb5_key
find_cached_dkey(struct derived_key *list, const krb5_data *constant)
{
    for (; list; list = list->next) {
        if (data_eq(list->constant, *constant)) {
            krb5_k_reference_key(NULL, list->dkey);
            return list->dkey;
        }
    }
    return NULL;
}

static krb5_error_code
add_cached_dkey(krb5_key key, const krb5_data *constant,
                const krb5_keyblock *dkeyblock, krb5_key *cached_dkey)
{
    krb5_key dkey;
    krb5_error_code ret;
    struct derived_key *dkent = NULL;
    char *data = NULL;

    /* Allocate fields for the new entry. */
    dkent = malloc(sizeof(*dkent));
    if (dkent == NULL)
        goto cleanup;
    data = k5memdup(constant->data, constant->length, &ret);
    if (data == NULL)
        goto cleanup;
    ret = krb5_k_create_key(NULL, dkeyblock, &dkey);
    if (ret != 0)
        goto cleanup;

    /* Add the new entry to the list. */
    dkent->dkey = dkey;
    dkent->constant.data = data;
    dkent->constant.length = constant->length;
    dkent->next = key->derived;
    key->derived = dkent;

    /* Return a "copy" of the cached key. */
    krb5_k_reference_key(NULL, dkey);
    *cached_dkey = dkey;
    return 0;

cleanup:
    free(dkent);
    free(data);
    return ENOMEM;
}

static krb5_error_code
derive_random_rfc3961(const struct krb5_enc_provider *enc,
                      krb5_key inkey, krb5_data *outrnd,
                      const krb5_data *in_constant)
{
    size_t blocksize, keybytes, n;
    krb5_error_code ret;
    krb5_data block = empty_data();

    blocksize = enc->block_size;
    keybytes = enc->keybytes;

    if (blocksize == 1)
        return KRB5_BAD_ENCTYPE;
    if (inkey->keyblock.length != enc->keylength || outrnd->length != keybytes)
        return KRB5_CRYPTO_INTERNAL;

    /* Allocate encryption data buffer. */
    ret = alloc_data(&block, blocksize);
    if (ret)
        return ret;

    /* Initialize the input block. */
    if (in_constant->length == blocksize) {
        memcpy(block.data, in_constant->data, blocksize);
    } else {
        krb5int_nfold(in_constant->length * 8,
                      (unsigned char *) in_constant->data,
                      blocksize * 8, (unsigned char *) block.data);
    }

    /* Loop encrypting the blocks until enough key bytes are generated. */
    n = 0;
    while (n < keybytes) {
        ret = encrypt_block(enc, inkey, &block);
        if (ret)
            goto cleanup;

        if ((keybytes - n) <= blocksize) {
            memcpy(outrnd->data + n, block.data, (keybytes - n));
            break;
        }

        memcpy(outrnd->data + n, block.data, blocksize);
        n += blocksize;
    }

cleanup:
    zapfree(block.data, blocksize);
    return ret;
}

/*
 * NIST SP800-108 KDF in feedback mode (section 5.2).
 * Parameters:
 *   - CMAC (with enc as the enc provider) is the PRF.
 *   - A block counter of four bytes is used.
 *   - Label is the key derivation constant.
 *   - Context is empty.
 *   - Four bytes are used to encode the output length in the PRF input.
 */
static krb5_error_code
derive_random_sp800_108_feedback_cmac(const struct krb5_enc_provider *enc,
                                      krb5_key inkey, krb5_data *outrnd,
                                      const krb5_data *in_constant)
{
    krb5_error_code ret = KRB5_CRYPTO_INTERNAL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[7];
    size_t i = 0;
    char *cipher;
    static unsigned char zeroes[16];

    memset(zeroes, 0, sizeof(zeroes));

    if (enc->keylength == 16)
        cipher = "CAMELLIA-128-CBC";
    else if (enc->keylength == 32)
        cipher = "CAMELLIA-256-CBC";
    else
        goto done;

    kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    if (!kdf)
        goto done;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto done;

    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE,
                                                   "FEEDBACK", 0);
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
                                                   "CMAC", 0);
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER,
                                                   cipher, 0);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    inkey->keyblock.contents,
                                                    inkey->keyblock.length);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                    in_constant->data,
                                                    in_constant->length);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED,
                                                    zeroes, sizeof(zeroes));
    params[i] = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        goto done;
    } else if (EVP_KDF_derive(kctx, (unsigned char *)outrnd->data,
                              outrnd->length) <= 0) {
        goto done;
    }

    ret = 0;
done:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

/*
 * NIST SP800-108 KDF in counter mode (section 5.1).
 * Parameters:
 *   - HMAC (with hash as the hash provider) is the PRF.
 *   - A block counter of four bytes is used.
 *   - Four bytes are used to encode the output length in the PRF input.
 *
 * There are no uses requiring more than a single PRF invocation.
 */
krb5_error_code
k5_sp800_108_counter_hmac(const struct krb5_hash_provider *hash,
                          krb5_key inkey, krb5_data *outrnd,
                          const krb5_data *label, const krb5_data *context)
{
    krb5_error_code ret = KRB5_CRYPTO_INTERNAL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6];
    size_t i = 0;
    char *digest;

    if (!strcmp(hash->hash_name, "SHA1"))
        digest = "SHA1";
    else if (!strcmp(hash->hash_name, "SHA-256"))
        digest = "SHA256";
    else if (!strcmp(hash->hash_name, "SHA-384"))
        digest = "SHA384";
    else
        goto done;

    kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    if (!kdf)
        goto done;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto done;

    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   digest, 0);
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
                                                   "HMAC", 0);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    inkey->keyblock.contents,
                                                    inkey->keyblock.length);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                    context->data,
                                                    context->length);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                    label->data,
                                                    label->length);
    params[i] = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        goto done;
    } else if (EVP_KDF_derive(kctx, (unsigned char *)outrnd->data,
                              outrnd->length) <= 0) {
        goto done;
    }

    ret = 0;
done:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

krb5_error_code
krb5int_derive_random(const struct krb5_enc_provider *enc,
                      const struct krb5_hash_provider *hash,
                      krb5_key inkey, krb5_data *outrnd,
                      const krb5_data *in_constant, enum deriv_alg alg)
{
    krb5_data empty = empty_data();

    switch (alg) {
    case DERIVE_RFC3961:
        return derive_random_rfc3961(enc, inkey, outrnd, in_constant);
    case DERIVE_SP800_108_CMAC:
        return derive_random_sp800_108_feedback_cmac(enc, inkey, outrnd,
                                                     in_constant);
    case DERIVE_SP800_108_HMAC:
        return k5_sp800_108_counter_hmac(hash, inkey, outrnd, in_constant,
                                         &empty);
    default:
        return EINVAL;
    }
}

/*
 * Compute a derived key into the keyblock outkey.  This variation on
 * krb5int_derive_key does not cache the result, as it is only used
 * directly in situations which are not expected to be repeated with
 * the same inkey and constant.
 */
krb5_error_code
krb5int_derive_keyblock(const struct krb5_enc_provider *enc,
                        const struct krb5_hash_provider *hash,
                        krb5_key inkey, krb5_keyblock *outkey,
                        const krb5_data *in_constant, enum deriv_alg alg)
{
    krb5_error_code ret;
    krb5_data rawkey = empty_data();

    /* Allocate a buffer for the raw key bytes. */
    ret = alloc_data(&rawkey, enc->keybytes);
    if (ret)
        goto cleanup;

    /* Derive pseudo-random data for the key bytes. */
    ret = krb5int_derive_random(enc, hash, inkey, &rawkey, in_constant, alg);
    if (ret)
        goto cleanup;

    /* Postprocess the key. */
    ret = krb5_c_random_to_key(NULL, inkey->keyblock.enctype, &rawkey, outkey);

cleanup:
    zapfree(rawkey.data, enc->keybytes);
    return ret;
}

krb5_error_code
krb5int_derive_key(const struct krb5_enc_provider *enc,
                   const struct krb5_hash_provider *hash,
                   krb5_key inkey, krb5_key *outkey,
                   const krb5_data *in_constant, enum deriv_alg alg)
{
    krb5_keyblock keyblock;
    krb5_error_code ret;
    krb5_key dkey;

    *outkey = NULL;

    /* Check for a cached result. */
    dkey = find_cached_dkey(inkey->derived, in_constant);
    if (dkey != NULL) {
        *outkey = dkey;
        return 0;
    }

    /* Derive into a temporary keyblock. */
    keyblock.length = enc->keylength;
    keyblock.contents = malloc(keyblock.length);
    keyblock.enctype = inkey->keyblock.enctype;
    if (keyblock.contents == NULL)
        return ENOMEM;
    ret = krb5int_derive_keyblock(enc, hash, inkey, &keyblock, in_constant,
                                  alg);
    if (ret)
        goto cleanup;

    /* Cache the derived key. */
    ret = add_cached_dkey(inkey, in_constant, &keyblock, &dkey);
    if (ret != 0)
        goto cleanup;

    *outkey = dkey;

cleanup:
    zapfree(keyblock.contents, keyblock.length);
    return ret;
}
