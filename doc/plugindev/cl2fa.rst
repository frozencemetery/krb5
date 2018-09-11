.. _cl2fa_plugin:

Client 2-Factor Authentication interface (cl2fa)
================================================

The cl2fa interface was first introduced in release 1.17 along with
the kdc2fa interface.  It allows modules to supply implementations of
second factor types for SPAKE (see SPAKE RFC for more information).
For a detailed description of the cl2fa interface, see the header file
``<krb5/cl2fa_plugin.h>``.

Modules respond to SPAKE SecondFactor challenges using the **respond**
function.  Additionally, modules can create and destroy module
data objects using **init** and **fini**.  The data has type
krb5_cl2fa_moddata, which should be cast to the appropriate internal
type.

If a module requires multiple round-trips for second-factor validation
to complete, it may provide an **encdata** function to handle these
additional messages.  Request-scoped data may be kept in reqdata,
which has type krb5_clfa_reqdata, and should be cast to the
appropriate internal type.  This data is destroyed in
**request_fini**.

cl2fa modules can optionally retrieve components of, and modify, the
SPAKE preauth state.  They are provided access to the preauth module's
callback system (**cb** and **rock**).  See the header file
``<krb5/clpreauth_plugin.h>`` for a detailed description of the
functionality this provides.
