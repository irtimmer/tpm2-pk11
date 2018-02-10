TPM2 PK11
==========

TPM2 PK11 provide a PKCS#11 backend for a TPM 2.0 chip.
This can be used to secure your SSH keys.

NOTICE: Currently only the OpenSSH client is supported

## SSH Usage

1. Create key's
```
mkdir ~/.tpm2 && cd ~/.tpm2

# Create a primary key with hash algorithm sha256 and key algorithm rsa
# and store the object context in a file (po.ctx)
tpm2_createprimary -H o -g sha256 -G rsa -C po.ctx

# now create an object that can be loaded into the tpm with parent
# object from file (po.ctx) using hash algorithm sha256 and key algorithm rsa
# output the public and private keys to key.pub|priv
tpm2_create -c po.ctx -g sha256 -G rsa -u key.pub -r key.priv

# load the private and public keys into the TPM's transient memory
tpm2_load -c po.ctx -u key.pub -r key.priv -C obj.ctx

# make the object persistent, specifying a valid handle
tpm2_evictcontrol -A o -c obj.ctx -H 0x81010010

rm key.name *.ctx
```
2. Create configuration file and change it for your setup
```
cp config.sample ~/.tpm2/config
```
3. Extract public key
```
ssh-keygen -D libtpm2-pk11.so
```
4. Use your TPM key
```
ssh -I libtpm2-pk11.so ssh.example.com
```
or add the PKCS#11 module to your ssh config in `~/.ssh/config`:
```
Host *
    PKCS11Provider libtpm2-pk11.so
```

## Contribute

1. Fork us
2. Write code
3. Send Pull Requests

## Copyright and license

Copyright 2017 Iwan Timmer. Distributed under the GNU LGPL v2.1. For full terms see the LICENSE file
