/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/init.c - Module init and cleanup functions */
/*
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "crypto_int.h"

#ifdef HAVE_OSSL_PROVIDER_LOAD

/*
 * Starting in OpenSSL 3, algorithms are grouped into containers called
 * "providers", not all of which are loaded by default.  At time of writing,
 * we need MD4 and RC4 from the legacy provider.  Oddly, 3DES is not in
 * legacy.
 */

#include <openssl/provider.h>

OSSL_PROVIDER *legacy_provider = NULL;
OSSL_PROVIDER *default_provider = NULL;

int
krb5int_crypto_impl_init(void)
{
    legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    default_provider = OSSL_PROVIDER_load(NULL, "default");

    /*
     * Someone might build openssl without the legacy provider.  They will
     * have a bad time, but some things will still work.  I don't know think
     * this configuration is worth supporting.
     */
    if (legacy_provider == NULL || default_provider == NULL)
        abort();

    return 0;
}

void
krb5int_crypto_impl_cleanup(void)
{
    if (legacy_provider != NULL)
        OSSL_PROVIDER_unload(legacy_provider);
    if (default_provider != NULL)
        OSSL_PROVIDER_unload(default_provider);

    legacy_provider = NULL;
    default_provider = NULL;
}

#else /* !HAVE_OSSL_PROVIDER_LOAD */

int
krb5int_crypto_impl_init(void)
{
    return 0;
}

void
krb5int_crypto_impl_cleanup(void)
{
}

#endif
