/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/krb5/hotfind_plugin.h - hotfind plugin interface */
/*
 * Copyright (C) 2019 by Red Hat, Inc.
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

/*
 * Declarations for hotfind plugin module implementors.
 *
 * The hotfind pluggable interface currently has only one supported major
 * version, which is 2.  Major version 2 has a current minor version number of
 * 1.  (Version 1 was not used, but as this plugin supersedes the old "locate"
 * plugin, we use 2 for clarity.)
 *
 * hotfind plugin modules should define a function named
 * hotfind_<modulename>_initvt, matching the signature:
 *
 *   krb5_error_code
 *   hotfind_modname_initvt(krb5_context context, int maj_ver, int min_ver,
 *                          krb5_plugin_vtable vtable);
 *
 * The initvt function should:
 *
 * - Check that the supplied maj_ver number is supported by the module, or
 *   return KRB5_PLUGIN_VER_NOTSUPP if it is not.
 *
 * - Cast the vtable pointer as appropriate for maj_ver:
 *   maj_ver == 2: Cast to krb5_hotfind_vtable
 *
 * - Initialize the methods of the vtable, stopping as appropriate for the
 *   supplied min_ver.  Optional methods may be left uninitialized.
 *
 * Memory for the vtable is allocated by the caller, not by the module.
 */

#ifndef KRB5_HOTFIND_PLUGIN_H
#define KRB5_HOTFIND_PLUGIN_H

#include <krb5/krb5.h>

/* Abstract module datatype. */
typedef struct krb5_hotfind_moddata_st *krb5_hotfind_moddata;

enum locate_service_type {
    locate_service_kdc = 1,
    locate_service_master_kdc,
    locate_service_kadmin,
    locate_service_krb524,
    locate_service_kpasswd
};

/*
 * Optional: Initialize module data.  Return 0 on success,
 * KRB5_PLUGIN_NO_HANDLE if the module is inoperable (due to configuration, for
 * example), and any other error code to abort KDC startup.  Optionally set
 * *data_out to a module data object to be passed to future calls.
 */
typedef krb5_error_code
(*krb5_hotfind_init_fn)(krb5_context context, krb5_hotfind_moddata *data_out);

/* Optional: Clean up module data. */
typedef void
(*krb5_hotfind_fini_fn)(krb5_context context, krb5_hotfind_moddata moddata);

/*
 * Plugins will call this function to add servers in response to a lookup.  If
 * DNS lookup has been performed by the hotfind plugin, it may supply this
 * information in addr.  Otherwise krb5 will perform the lookup if needed.
 * Servers will be tried in the order in which they are added based on the
 * preferred transport method.
 *
 * - cbdata is internal data provided to the locator plugin
 * - hostname is the desired hostname to use, which can be NULL
 * - port is the desired port, or 0 for the service type's default
 * - transport must not be TCP_OR_UDP (call function once per type instead)
 * - uri_path is NULL except for HTTPS transports
 * - addr is either NULL or the result of a DNS lookup
 * - addrlen is the length of addr, or 0 if no DNS lookup was performed
 */
typedef void
(*krb5_hotfind_callback_fn)(void *cbdata, const char *hostname, uint16_t port,
                            int tcp_only, const char *uri_path,
                            int family, size_t addrlen,
                            const struct sockaddr *addr);

/*
 * Mandatory:
 * Calls cbfunc (see above) once for each server that results from lookup.
 * Returns 0 unless there was a fatal error, or -1 to indicate that the
 * service should not be looked up.
 *
 * - cbdata is internal data to pass to cbfunc
 * - a transport_req value of TCP_OR_UDP indicates no restriction on type
 */
typedef krb5_error_code
(*krb5_hotfind_find_fn)(krb5_context context, krb5_hotfind_moddata moddata,
                        enum locate_service_type svc,
                        const char *realm, int no_udp,
                        krb5_hotfind_callback_fn cbfunc, void *cbdata);

typedef struct krb5_hotfind_vtable_st {
    const char *name;
    krb5_hotfind_init_fn init;
    krb5_hotfind_fini_fn fini;
    krb5_hotfind_find_fn find;
} *krb5_hotfind_vtable;

#endif /* KRB5_HOTFIND_PLUGIN_H */
