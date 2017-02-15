#!/usr/bin/python

# Copyright (C) 2017 Red Hat, Inc.
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Red Hat, Inc., nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
# OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from k5test import *

# TODO: We need to talk about a better solution.  For now, create a custom
# libgssapi_krb5.so modified to use a custom mechanism configuration file.
cwd = os.getcwd()

usrlocal = "/usr/local/etc/gss/mech.d"
magic = "_" * (len(usrlocal) - len("mech.d"))
mechdir = "mech.d" + magic

lib = "../../lib/libgssapi_krb5.so"

if os.path.exists(mechdir):
    shutil.rmtree(mechdir)
os.makedirs(mechdir)

lib = os.path.realpath(lib)
with open(lib, "rb") as f:
    data = f.read()

shutil.move(lib, lib + ".bak")

# TODO: Doing this properly requires reading the configuration from autotools.
# However, we won't be using this approach anyway, so just hardcode the
# default for now.
data = data.replace("/usr/local/etc/gss/mech.d", mechdir)

with open(lib, "wb") as f:
    f.write(data)

mechlib = os.path.abspath("../../plugins/gssapi/interposer/reenter.so")
# TODO: probably shouldn't use the gssproxy OID here
MECH_CONF_TEMPLATE = """
gssproxy_v1	2.16.840.1.113730.3.8.15.1	${PROXYMECH}	<interposer>
"""
mech_conf = MECH_CONF_TEMPLATE.replace("${PROXYMECH}", mechlib)
with open(mechdir + "/interpose.conf", "w") as f:
    f.write(mech_conf)

print("WE RUN THIS")
ret = subprocess.call(["./t_gssapi.py"] + sys.argv)

# shutil.copy(lib, "/tmp")

shutil.copy(lib + ".bak", lib)

if ret != 0:
    fail("interpose tests; see above")
else:
    success("Interposer tests")
    
print "done"
