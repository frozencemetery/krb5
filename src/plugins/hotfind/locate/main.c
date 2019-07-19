/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/hotfind/locate/main.c - hotfind shim for old locate interface */
/* TODO this needs a copyright header */

#include "k5-int.h"
#include "fake-addrinfo.h"
#include "os-proto.h"

#include <krb5/hotfind_plugin.h>
#include <krb5/locate_plugin.h>

#if TARGET_OS_MAC
static const char *objdirs[] = { KRB5_PLUGIN_BUNDLE_DIR,
                                 LIBDIR "/krb5/plugins/libkrb5",
                                 NULL }; /* should be a list */
#else
static const char *objdirs[] = { LIBDIR "/krb5/plugins/libkrb5", NULL };
#endif

/* krb5_hotfind_moddata is a list of these. */
struct locate_module {
    struct krb5plugin_service_locate_ftable *vtbl;
    void *moddata;
};

struct locate_callback_data {
    krb5_hotfind_callback_fn cbfunc;
    void *cbdata;
};

static krb5_error_code
locate_init(krb5_context ctx, krb5_hotfind_moddata *data_out)
{
    krb5_error_code ret = 0;
    void **ptrs = NULL;
    int i, count;
    struct locate_module *mods;

    *data_out = NULL;
    
    if (!PLUGIN_DIR_OPEN(&ctx->libkrb5_plugins)) {
        ret = krb5int_open_plugin_dirs(objdirs, NULL, &ctx->libkrb5_plugins,
                                       &ctx->err);
        if (ret)
            goto done;
    }

    ret = krb5int_get_plugin_dir_data(&ctx->libkrb5_plugins,
                                      "service_locator", &ptrs, &ctx->err);
    if (ret) {
        ret = KRB5_PLUGIN_NO_HANDLE;
        goto done;
    }

    for (count = 0; ptrs != NULL && ptrs[count] != NULL; count++);
    if (count == 0)
        goto done;

    mods = k5calloc(sizeof(*mods), count + 1, &ret);
    if (mods == NULL)
        goto done;

    for (i = 0; ptrs[i] != NULL; i++) {
        struct krb5plugin_service_locate_ftable *vt = ptrs[i];
        if (vt->init != NULL) {
            ret = vt->init(ctx, &mods[i].moddata);
            if (ret)
                continue;
        }
        mods[count++].vtbl = vt;
    }

    if (count == 0)
        free(mods);
    else
        *data_out = (void *)mods;
        
done:
    krb5int_free_plugin_dir_data(ptrs);
    return ret;
}

static void
locate_fini(krb5_context ctx, krb5_hotfind_moddata moddata)
{
    struct locate_module *mods = (void *)moddata;

    free(mods);
}

static int
locate_callback(void *cbdata, int socktype, struct sockaddr *sa)
{
    struct locate_callback_data *data = cbdata;
    size_t addrlen;

    if (sa->sa_family == AF_INET)
        addrlen = sizeof(struct sockaddr_in);
    else if (sa->sa_family == AF_INET6)
        addrlen = sizeof(struct sockaddr_in6);
    else
        return 0;

    data->cbfunc(data->cbdata, NULL, 0, socktype == SOCK_STREAM, NULL,
                 sa->sa_family, addrlen, sa);

    return 0;
}

static krb5_error_code
locate_find(krb5_context ctx, krb5_hotfind_moddata moddata,
            enum locate_service_type svc, const char *realm, int no_udp,
            krb5_hotfind_callback_fn cbfunc, void *cbdata)
{
    int socktype;
    krb5_error_code ret;
    struct locate_module *mods = (void *)moddata, *m;
    struct locate_callback_data locate_cbdata;

    if (mods == NULL)
        return 0;

    socktype = no_udp ? SOCK_STREAM : SOCK_DGRAM;

    locate_cbdata.cbfunc = cbfunc;
    locate_cbdata.cbdata = cbdata;
    
    for (m = mods; m != NULL; m++) {
        ret = m->vtbl->lookup(m->moddata, svc, realm, socktype, AF_UNSPEC,
                              locate_callback, &locate_cbdata);
        if (ret == 0 && !no_udp) {
            /* First request was for UDP - retry for TCP. */
            ret = m->vtbl->lookup(m->moddata, svc, realm, SOCK_STREAM,
                                  AF_UNSPEC, locate_callback, &locate_cbdata);
            if (ret == KRB5_PLUGIN_NO_HANDLE)
                ret = 0;
        }

        if (ret != KRB5_PLUGIN_NO_HANDLE)
            break;
    }

    return ret;
}

krb5_error_code
hotfind_locate_initvt(krb5_context ctx, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable_in);
krb5_error_code
hotfind_locate_initvt(krb5_context ctx, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable_in)
{
    krb5_hotfind_vtable vt;

    if (maj_ver != 2)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_hotfind_vtable)vtable_in;
    vt->name = "locate";
    vt->init = locate_init;
    vt->fini = locate_fini;
    vt->find = locate_find;

    return 0;
}
