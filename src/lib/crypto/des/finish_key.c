/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char des_fin_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <sys/errno.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include <krb5/des.h>

/*
	does any necessary clean-up on the eblock (such as releasing
	resources held by eblock->priv).

	returns: errors
 */

krb5_error_code mit_des_finish_key (DECLARG(krb5_encrypt_block *,eblock))
OLDDECLARG(krb5_encrypt_block *,eblock)
{
    bzero((char *)eblock->priv, sizeof(des_key_schedule));
    free(eblock->priv);
    eblock->priv = 0;
    /* free/clear other stuff here? */
    return 0;
}
