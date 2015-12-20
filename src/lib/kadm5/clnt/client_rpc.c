/* -*- mode: c; c-file-style: "bsd"; indent-tabs-mode: t -*- */
#include <gssrpc/rpc.h>
#include <kadm5/kadm_rpc.h>
#include <krb5.h>
#include <kadm5/admin.h>
#include <string.h>  /* for memset prototype */

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

void
cli_create_principal_2(generic_ret *res, cprinc_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, CREATE_PRINCIPAL,
		      (xdrproc_t) xdr_cprinc_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
                res->code = KADM5_RPC_ERROR;
	}
}

void
cli_create_principal3_2(generic_ret *res, cprinc3_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, CREATE_PRINCIPAL3,
		      (xdrproc_t) xdr_cprinc3_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
                res->code = KADM5_RPC_ERROR;
	}
}

void
cli_delete_principal_2(generic_ret *res, dprinc_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, DELETE_PRINCIPAL,
		      (xdrproc_t) xdr_dprinc_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_modify_principal_2(generic_ret *res, mprinc_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, MODIFY_PRINCIPAL,
		      (xdrproc_t) xdr_mprinc_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_rename_principal_2(generic_ret *res, rprinc_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, RENAME_PRINCIPAL,
		      (xdrproc_t) xdr_rprinc_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_get_principal_2(gprinc_ret *res, gprinc_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, GET_PRINCIPAL,
		      (xdrproc_t) xdr_gprinc_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_gprinc_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_get_princs_2(gprincs_ret *res, gprincs_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, GET_PRINCS,
		      (xdrproc_t) xdr_gprincs_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_gprincs_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_chpass_principal_2(generic_ret *res, chpass_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, CHPASS_PRINCIPAL,
		      (xdrproc_t) xdr_chpass_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_chpass_principal3_2(generic_ret *res, chpass3_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, CHPASS_PRINCIPAL3,
		      (xdrproc_t) xdr_chpass3_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_setv4key_principal_2(generic_ret *res, setv4key_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, SETV4KEY_PRINCIPAL,
		      (xdrproc_t) xdr_setv4key_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_setkey_principal_2(generic_ret *res, setkey_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, SETKEY_PRINCIPAL,
		      (xdrproc_t) xdr_setkey_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_setkey_principal3_2(generic_ret *res, setkey3_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, SETKEY_PRINCIPAL3,
		      (xdrproc_t) xdr_setkey3_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_setkey_principal4(generic_ret *res, setkey4_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, SETKEY_PRINCIPAL4,
		      (xdrproc_t)xdr_setkey4_arg, (caddr_t)argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_chrand_principal_2(chrand_ret *res, chrand_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, CHRAND_PRINCIPAL,
		      (xdrproc_t) xdr_chrand_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_chrand_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_chrand_principal3_2(chrand_ret *res, chrand3_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, CHRAND_PRINCIPAL3,
		      (xdrproc_t) xdr_chrand3_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_chrand_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_create_policy_2(generic_ret *res, cpol_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, CREATE_POLICY,
		      (xdrproc_t) xdr_cpol_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_delete_policy_2(generic_ret *res, dpol_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, DELETE_POLICY,
		      (xdrproc_t) xdr_dpol_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_modify_policy_2(generic_ret *res, mpol_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, MODIFY_POLICY,
		      (xdrproc_t) xdr_mpol_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_get_policy_2(gpol_ret *res, gpol_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, GET_POLICY,
		      (xdrproc_t) xdr_gpol_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_gpol_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_get_pols_2(gpols_ret *res, gpols_arg *argp, CLIENT *clnt)
{
	if (clnt_call(clnt, GET_POLS,
		      (xdrproc_t) xdr_gpols_arg, (caddr_t) argp,
		      (xdrproc_t)xdr_gpols_ret, (caddr_t)res,
		      TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
	}
}

void
cli_get_privs_2(getprivs_ret *res, void *argp, CLIENT *clnt)
{
     if (clnt_call(clnt, GET_PRIVS,
		   (xdrproc_t) xdr_u_int32, (caddr_t) argp,
		   (xdrproc_t)xdr_getprivs_ret, (caddr_t)res,
		   TIMEOUT) != RPC_SUCCESS) {
		res->code = KADM5_RPC_ERROR;
     }
}

void
cli_init_2(generic_ret *res, void *argp, CLIENT *clnt)
{
     if (clnt_call(clnt, INIT,
		   (xdrproc_t) xdr_u_int32, (caddr_t) argp,
		   (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		   TIMEOUT) != RPC_SUCCESS) {
	  res->code = KADM5_RPC_ERROR;
     }
}

void
cli_purgekeys_2(generic_ret *res, purgekeys_arg *argp, CLIENT *clnt)
{
     if (clnt_call(clnt, PURGEKEYS,
		   (xdrproc_t) xdr_purgekeys_arg, (caddr_t) argp,
		   (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		   TIMEOUT) != RPC_SUCCESS) {
	  res->code = KADM5_RPC_ERROR;
     }
}

void
cli_get_strings_2(gstrings_ret *res, gstrings_arg *argp, CLIENT *clnt)
{
     if (clnt_call(clnt, GET_STRINGS,
		   (xdrproc_t) xdr_gstrings_arg, (caddr_t) argp,
		   (xdrproc_t)xdr_gstrings_ret, (caddr_t)res,
		   TIMEOUT) != RPC_SUCCESS) {
	  res->code = KADM5_RPC_ERROR;
     }
}

void
cli_set_string_2(generic_ret *res, sstring_arg *argp, CLIENT *clnt)
{
     if (clnt_call(clnt, SET_STRING,
		   (xdrproc_t) xdr_sstring_arg, (caddr_t) argp,
		   (xdrproc_t)xdr_generic_ret, (caddr_t)res,
		   TIMEOUT) != RPC_SUCCESS) {
	  res->code = KADM5_RPC_ERROR;
     }
}

void
cli_get_principal_keys(getpkeys_ret *res, getpkeys_arg *argp, CLIENT *clnt)
{
     if (clnt_call(clnt, EXTRACT_KEYS,
		   (xdrproc_t)xdr_getpkeys_arg, (caddr_t)argp,
		   (xdrproc_t)xdr_getpkeys_ret, (caddr_t)res,
		   TIMEOUT) != RPC_SUCCESS) {
	  res->code = KADM5_RPC_ERROR;
     }
}
