.. _kdc2fa_plugin:

KDC 2-Factor Authentication interface (kdc2fa)
==============================================

The kdc2fa interface was first introduced in release 1.17 along with
the cl2fa interface.  It allows modules to supply implementations of
second factor types for SPAKE (see SPAKE RFC for more information).
For a detailed description of the kdc2fa interface, see the header
file ``<krb5/kdc2fa_plugin.h>``.

Modules create (possibly empty) challenges using **challenge**, and
client responses are passed to **verify**.  Additionally, modules can
create and destroy per-module data objects using **init** and
**fini**.  The data has the type krb5_kdc2fa_moddata, which should be
cast to the appropriate internal type.  Modules may also store
per-request data; this data must be serialized, since it will be
stored in the cookie.

kdc2fa modules can optionally retrieve components of, and modify, the
SPAKE preauth state.  They are provided access to the preauth module's
callback system (**cb** and **rock**).  See the header file
``<krb5/kdcpreauth_plugin.h>`` for a detailed description of the
functionality this provides.

The **challenge** and **verify** methods can be implemented
asynchronously.  Because of this, they do not return values directly
to the caller, but instead must invoke responder functions with their
results.  A synchronous implementation can invoke the responder
function immediately.  An asynchronous implementation can use the
callback in **cb** to access an event context for use with the
libverto_ API.

.. _libverto: https://github.com/latchset/libverto
