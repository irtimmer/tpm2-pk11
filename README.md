TPM2 Utils
==========

TPM2 Utils provide a PKCS#11 backend for a TPM 2.0 chip.
This can be used to secure your SSH keys.

NOTICE: Currently only the OpenSSH client is supported

## SSH Usage

1. Create key's
```
mkdir ~/.tpm2
tpm2_getpubek -H 0x81010000 -g 0x01 -f ~/.tpm2/ek.pub
tpm2_getpubak -E 0x81010000 -k 0x81010010 -f ~/.tpm2/key.pub -n ~/.tpm2/key.name
```
2. Create configuration file in ~/.tpm2
```
echo key ~/tpm2/key.pub > ~/.tpm2/config
echo "key_handle 0x81010010" > ~/.tpm2/config
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

Copyright 2017 Iwan Timmer. Distributed under the GNU LGPL v2. For full terms see the LICENSE file
