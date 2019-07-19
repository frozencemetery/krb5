/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/hotfind/profile/main.c - hotfind plugin for profile lookup */
/* TODO this needs a copyright header */

#include "fake-addrinfo.h"
#include "k5-int.h"
#include "../../../lib/krb5/os/os-proto.h"

#include <krb5/hotfind_plugin.h>
#include <krb5/plugin.h>

static void
parse_uri_if_https(const char *host_or_uri, k5_transport *transport,
                   const char **host, const char **uri_path)
{
    char *cp;

    if (strncmp(host_or_uri, "https://", 8) == 0) {
        *transport = HTTPS;
        *host = host_or_uri + 8;

        cp = strchr(*host, '/');
        if (cp != NULL) {
            *cp = '\0';
            *uri_path = cp + 1;
        }
    }
}

static krb5_error_code
profile_find(krb5_context context, krb5_hotfind_moddata moddata,
             enum locate_service_type svc, const char *realm, int no_udp,
             krb5_hotfind_callback_fn cbfunc, void *cbdata)
{
    krb5_error_code ret;
    const char *profname;
    char *host = NULL, **hostlist = NULL;
    int i, dflport;
    const char *realm_srv_names[4];
    struct servent *serv;
    k5_transport this_transport;

    /* We used to use /etc/services for these, but enough systems have old,
     * crufty, wrong settings that this is probably better. */
    switch (svc) {
    case locate_service_kdc:
        profname = KRB5_CONF_KDC;
        dflport = KRB5_DEFAULT_PORT;
        break;
    case locate_service_master_kdc:
        profname = KRB5_CONF_MASTER_KDC;
        dflport = KRB5_DEFAULT_PORT;
        break;
    case locate_service_kadmin:
        profname = KRB5_CONF_ADMIN_SERVER;
        dflport = DEFAULT_KADM5_PORT;
        break;
    case locate_service_krb524:
        profname = KRB5_CONF_KRB524_SERVER;
        serv = getservbyname("krb524", "udp");
        dflport = serv ? serv->s_port : 4444;
        break;
    case locate_service_kpasswd:
        profname = KRB5_CONF_KPASSWD_SERVER;
        dflport = DEFAULT_KPASSWD_PORT;
        break;
    default:
        return EBUSY; /* Should never get here. */
    }
    
    realm_srv_names[0] = KRB5_CONF_REALMS;
    realm_srv_names[1] = realm;
    realm_srv_names[2] = profname;
    realm_srv_names[3] = 0;
    ret = profile_get_values(context->profile, realm_srv_names, &hostlist);
    if (ret) {
        if (ret == PROF_NO_SECTION || ret == PROF_NO_RELATION)
            ret = 0;
        goto done;
    }

    for (i = 0; hostlist[i] != NULL; i++) {
        const char *uri_path = NULL, *hostspec = NULL;
        int default_port, port_num;

        hostspec = hostlist[i];

        parse_uri_if_https(hostspec, &this_transport, &hostspec, &uri_path);
        default_port = (this_transport == HTTPS) ? 443 : dflport;
        ret = k5_parse_host_string(hostspec, default_port, &host, &port_num);
        if (ret == 0 && host == NULL)
            ret = EINVAL;
        if (ret)
            goto done;

        cbfunc(cbdata, host, port_num, !no_udp || this_transport == HTTPS,
               uri_path, AF_UNSPEC, 0, NULL);
        free(host);
        host = NULL;
    }

done:
    free(host);
    profile_free_list(hostlist);
    return ret;
}

krb5_error_code
hotfind_profile_initvt(krb5_context ctx, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable_in);
krb5_error_code
hotfind_profile_initvt(krb5_context ctx, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable_in)
{
    krb5_hotfind_vtable vt;

    if (maj_ver != 2)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_hotfind_vtable)vtable_in;
    vt->name = "profile";
    vt->init = NULL;
    vt->fini = NULL;
    vt->find = profile_find;

    return 0;
}
