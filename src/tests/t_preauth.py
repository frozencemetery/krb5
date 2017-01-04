#!/usr/bin/python
from k5test import *

# Test that the kdcpreauth client_keyblock() callback matches the key
# indicated by the etype info, and returns NULL if no key was selected.
testpreauth = os.path.join(buildtop, 'plugins', 'preauth', 'test', 'test.so')
conf = {'plugins': {'kdcpreauth': {'module': 'test:' + testpreauth},
                    'clpreauth': {'module': 'test:' + testpreauth}}}
realm = K5Realm(create_host=False, get_creds=False, krb5_conf=conf)
realm.run([kadminl, 'modprinc', '+requires_preauth', realm.user_princ])
realm.run([kadminl, 'setstr', realm.user_princ, 'teststring', 'testval'])
realm.run([kadminl, 'addprinc', '-nokey', '+requires_preauth', 'nokeyuser'])
out = realm.run([kinit, realm.user_princ], input=password('user')+'\n')
if 'testval' not in out:
    fail('Decrypted string attribute not in kinit output')
out = realm.run([kinit, 'nokeyuser'], input=password('user')+'\n',
                expected_code=1)
if 'no key' not in out:
    fail('Expected "no key" message not in kinit output')

# Exercise KDC_ERR_MORE_PREAUTH_DATA_REQUIRED and secure cookies.
realm.run([kadminl, 'setstr', realm.user_princ, '2rt', 'secondtrip'])
out = realm.run([kinit, realm.user_princ], input=password('user')+'\n')
if '2rt: secondtrip' not in out:
    fail('multi round-trip cookie test')

# Test that multiple stepwise initial creds operations can be
# performed with the same krb5_context, with proper tracking of
# clpreauth module request handles.
realm.run([kadminl, 'addprinc', '-pw', 'pw', 'u1'])
realm.run([kadminl, 'addprinc', '+requires_preauth', '-pw', 'pw', 'u2'])
realm.run([kadminl, 'addprinc', '+requires_preauth', '-pw', 'pw', 'u3'])
realm.run([kadminl, 'setstr', 'u2', '2rt', 'extra'])
out = realm.run(['./icinterleave', 'pw', 'u1', 'u2', 'u3'])
if out != ('step 1\nstep 2\nstep 3\nstep 1\nfinish 1\nstep 2\nno attr\n'
           'step 3\nno attr\nstep 2\n2rt: extra\nstep 3\nfinish 3\nstep 2\n'
           'finish 2\n'):
    fail('unexpected output from icinterleave')

success('Pre-authentication framework tests')
