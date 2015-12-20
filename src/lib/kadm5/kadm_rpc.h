/* -*- mode: c; c-file-style: "bsd"; indent-tabs-mode: t -*- */
#ifndef __KADM_RPC_H__
#define __KADM_RPC_H__

#include <gssrpc/types.h>

#include	<krb5.h>
#include	<kadm5/admin.h>

struct cprinc_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
	char *passwd;
};
typedef struct cprinc_arg cprinc_arg;

struct cprinc3_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
	char *passwd;
};
typedef struct cprinc3_arg cprinc3_arg;

struct generic_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
};
typedef struct generic_ret generic_ret;

struct dprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
};
typedef struct dprinc_arg dprinc_arg;

struct mprinc_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
};
typedef struct mprinc_arg mprinc_arg;

struct rprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal src;
	krb5_principal dest;
};
typedef struct rprinc_arg rprinc_arg;

struct gprincs_arg {
	krb5_ui_4 api_version;
	char *exp;
};
typedef struct gprincs_arg gprincs_arg;

struct gprincs_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	char **princs;
	int count;
};
typedef struct gprincs_ret gprincs_ret;

struct chpass_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	char *pass;
};
typedef struct chpass_arg chpass_arg;

struct chpass3_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
	char *pass;
};
typedef struct chpass3_arg chpass3_arg;

struct setv4key_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_keyblock *keyblock;
};
typedef struct setv4key_arg setv4key_arg;

struct setkey_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_keyblock *keyblocks;
	int n_keys;
};
typedef struct setkey_arg setkey_arg;

struct setkey3_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
	krb5_keyblock *keyblocks;
	int n_keys;
};
typedef struct setkey3_arg setkey3_arg;

struct setkey4_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	kadm5_key_data *key_data;
	int n_key_data;
};
typedef struct setkey4_arg setkey4_arg;

struct chrand_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
};
typedef struct chrand_arg chrand_arg;

struct chrand3_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
};
typedef struct chrand3_arg chrand3_arg;

struct chrand_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	krb5_keyblock key;
	krb5_keyblock *keys;
	int n_keys;
};
typedef struct chrand_ret chrand_ret;

struct gprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	long mask;
};
typedef struct gprinc_arg gprinc_arg;

struct gprinc_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	kadm5_principal_ent_rec rec;
};
typedef struct gprinc_ret gprinc_ret;

struct cpol_arg {
	krb5_ui_4 api_version;
	kadm5_policy_ent_rec rec;
	long mask;
};
typedef struct cpol_arg cpol_arg;

struct dpol_arg {
	krb5_ui_4 api_version;
	char *name;
};
typedef struct dpol_arg dpol_arg;

struct mpol_arg {
	krb5_ui_4 api_version;
	kadm5_policy_ent_rec rec;
	long mask;
};
typedef struct mpol_arg mpol_arg;

struct gpol_arg {
	krb5_ui_4 api_version;
	char *name;
};
typedef struct gpol_arg gpol_arg;

struct gpol_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	kadm5_policy_ent_rec rec;
};
typedef struct gpol_ret gpol_ret;

struct gpols_arg {
	krb5_ui_4 api_version;
	char *exp;
};
typedef struct gpols_arg gpols_arg;

struct gpols_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	char **pols;
	int count;
};
typedef struct gpols_ret gpols_ret;

struct getprivs_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	long privs;
};
typedef struct getprivs_ret getprivs_ret;

struct purgekeys_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	int keepkvno;
};
typedef struct purgekeys_arg purgekeys_arg;

struct gstrings_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
};
typedef struct gstrings_arg gstrings_arg;

struct gstrings_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	krb5_string_attr *strings;
	int count;
};
typedef struct gstrings_ret gstrings_ret;

struct sstring_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	char *key;
	char *value;
};
typedef struct sstring_arg sstring_arg;

struct getpkeys_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_kvno kvno;
};
typedef struct getpkeys_arg getpkeys_arg;

struct getpkeys_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	kadm5_key_data *key_data;
	int n_key_data;
};
typedef struct getpkeys_ret getpkeys_ret;

#define KADM 2112
#define KADMVERS 2
#define CREATE_PRINCIPAL 1
extern  void cli_create_principal_2(generic_ret *, cprinc_arg *, CLIENT *);
extern  void srv_create_principal_2(generic_ret *, cprinc_arg *, SERVER *);
#define DELETE_PRINCIPAL 2
extern  void cli_delete_principal_2(generic_ret *, dprinc_arg *, CLIENT *);
extern  void srv_delete_principal_2(generic_ret *, dprinc_arg *, SERVER *);
#define MODIFY_PRINCIPAL 3
extern  void cli_modify_principal_2(generic_ret *, mprinc_arg *, CLIENT *);
extern  void srv_modify_principal_2(generic_ret *, mprinc_arg *, SERVER *);
#define RENAME_PRINCIPAL 4
extern  void cli_rename_principal_2(generic_ret *, rprinc_arg *, CLIENT *);
extern  void srv_rename_principal_2(generic_ret *, rprinc_arg *, SERVER *);
#define GET_PRINCIPAL 5
extern  void cli_get_principal_2(gprinc_ret *, gprinc_arg *, CLIENT *);
extern  void srv_get_principal_2(gprinc_ret *, gprinc_arg *, SERVER *);
#define CHPASS_PRINCIPAL 6
extern  void cli_chpass_principal_2(generic_ret *, chpass_arg *, CLIENT *);
extern  void srv_chpass_principal_2(generic_ret *, chpass_arg *, SERVER *);
#define CHRAND_PRINCIPAL 7
extern  void cli_chrand_principal_2(chrand_ret *, chrand_arg *, CLIENT *);
extern  void srv_chrand_principal_2(chrand_ret *, chrand_arg *, SERVER *);
#define CREATE_POLICY 8
extern  void cli_create_policy_2(generic_ret *, cpol_arg *, CLIENT *);
extern  void srv_create_policy_2(generic_ret *, cpol_arg *, SERVER *);
#define DELETE_POLICY 9
extern  void cli_delete_policy_2(generic_ret *, dpol_arg *, CLIENT *);
extern  void srv_delete_policy_2(generic_ret *, dpol_arg *, SERVER *);
#define MODIFY_POLICY 10
extern  void cli_modify_policy_2(generic_ret *, mpol_arg *, CLIENT *);
extern  void srv_modify_policy_2(generic_ret *, mpol_arg *, SERVER *);
#define GET_POLICY 11
extern  void cli_get_policy_2(gpol_ret *, gpol_arg *, CLIENT *);
extern  void srv_get_policy_2(gpol_ret *, gpol_arg *, SERVER *);
#define GET_PRIVS 12
extern  void cli_get_privs_2(getprivs_ret *, void *, CLIENT *);
extern  void srv_get_privs_2(getprivs_ret *, krb5_ui_4 *, SERVER *);
#define INIT 13
extern  void cli_init_2(generic_ret *, void *, CLIENT *);
extern  void srv_init_2(generic_ret *, krb5_ui_4 *, SERVER *);
#define GET_PRINCS 14
extern  void cli_get_princs_2(gprincs_ret *, gprincs_arg *, CLIENT *);
extern  void srv_get_princs_2(gprincs_ret *, gprincs_arg *, SERVER *);
#define GET_POLS 15
extern  void cli_get_pols_2(gpols_ret *, gpols_arg *, CLIENT *);
extern  void srv_get_pols_2(gpols_ret *, gpols_arg *, SERVER *);
#define SETKEY_PRINCIPAL 16
extern  void cli_setkey_principal_2(generic_ret *, setkey_arg *, CLIENT *);
extern  void srv_setkey_principal_2(generic_ret *, setkey_arg *, SERVER *);
#define SETV4KEY_PRINCIPAL 17
extern  void cli_setv4key_principal_2(generic_ret *, setv4key_arg *, CLIENT *);
extern  void srv_setv4key_principal_2(generic_ret *, setv4key_arg *, SERVER *);
#define CREATE_PRINCIPAL3 18
extern  void cli_create_principal3_2(generic_ret *, cprinc3_arg *, CLIENT *);
extern  void srv_create_principal3_2(generic_ret *, cprinc3_arg *, SERVER *);
#define CHPASS_PRINCIPAL3 19
extern  void cli_chpass_principal3_2(generic_ret *, chpass3_arg *, CLIENT *);
extern  void srv_chpass_principal3_2(generic_ret *, chpass3_arg *, SERVER *);
#define CHRAND_PRINCIPAL3 20
extern  void cli_chrand_principal3_2(chrand_ret *, chrand3_arg *, CLIENT *);
extern  void srv_chrand_principal3_2(chrand_ret *, chrand3_arg *, SERVER *);
#define SETKEY_PRINCIPAL3 21
extern  void cli_setkey_principal3_2(generic_ret *, setkey3_arg *, CLIENT *);
extern  void srv_setkey_principal3_2(generic_ret *, setkey3_arg *, SERVER *);
#define PURGEKEYS 22
extern  void cli_purgekeys_2(generic_ret *, purgekeys_arg *, CLIENT *);
extern  void srv_purgekeys_2(generic_ret *, purgekeys_arg *, SERVER *);
#define GET_STRINGS 23
extern  void cli_get_strings_2(gstrings_ret *, gstrings_arg *, CLIENT *);
extern  void srv_get_strings_2(gstrings_ret *, gstrings_arg *, SERVER *);
#define SET_STRING 24
extern  void cli_set_string_2(generic_ret *, sstring_arg *, CLIENT *);
extern  void srv_set_string_2(generic_ret *, sstring_arg *, SERVER *);
#define SETKEY_PRINCIPAL4 25
extern  void cli_setkey_principal4(generic_ret *, setkey4_arg *, CLIENT *);
extern  void srv_setkey_principal4(generic_ret *, setkey4_arg *, SERVER *);
#define EXTRACT_KEYS 26
extern void cli_get_principal_keys(getpkeys_ret *, getpkeys_arg *, CLIENT *);
extern void srv_get_principal_keys(getpkeys_ret *, getpkeys_arg *, SERVER *);

extern bool_t xdr_cprinc_arg ();
extern bool_t xdr_cprinc3_arg ();
extern bool_t xdr_generic_ret ();
extern bool_t xdr_dprinc_arg ();
extern bool_t xdr_mprinc_arg ();
extern bool_t xdr_rprinc_arg ();
extern bool_t xdr_gprincs_arg ();
extern bool_t xdr_gprincs_ret ();
extern bool_t xdr_chpass_arg ();
extern bool_t xdr_chpass3_arg ();
extern bool_t xdr_setv4key_arg ();
extern bool_t xdr_setkey_arg ();
extern bool_t xdr_setkey3_arg ();
extern bool_t xdr_setkey4_arg ();
extern bool_t xdr_chrand_arg ();
extern bool_t xdr_chrand3_arg ();
extern bool_t xdr_chrand_ret ();
extern bool_t xdr_gprinc_arg ();
extern bool_t xdr_gprinc_ret ();
extern bool_t xdr_kadm5_ret_t ();
extern bool_t xdr_kadm5_principal_ent_rec ();
extern bool_t xdr_kadm5_policy_ent_rec ();
extern bool_t	xdr_krb5_keyblock ();
extern bool_t	xdr_krb5_principal ();
extern bool_t	xdr_krb5_enctype ();
extern bool_t	xdr_krb5_octet ();
extern bool_t	xdr_krb5_int32 ();
extern bool_t	xdr_u_int32 ();
extern bool_t xdr_cpol_arg ();
extern bool_t xdr_dpol_arg ();
extern bool_t xdr_mpol_arg ();
extern bool_t xdr_gpol_arg ();
extern bool_t xdr_gpol_ret ();
extern bool_t xdr_gpols_arg ();
extern bool_t xdr_gpols_ret ();
extern bool_t xdr_getprivs_ret ();
extern bool_t xdr_purgekeys_arg ();
extern bool_t xdr_gstrings_arg ();
extern bool_t xdr_gstrings_ret ();
extern bool_t xdr_sstring_arg ();
extern bool_t xdr_krb5_string_attr ();
extern bool_t xdr_kadm5_key_data ();
extern bool_t xdr_getpkeys_arg ();
extern bool_t xdr_getpkeys_ret ();

#endif /* __KADM_RPC_H__ */
