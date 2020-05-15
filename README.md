### Deprecation Notice

This package is no longer maintained. Users are advised to switch to [tpm2-pkcs11](https://github.com/tpm2-software/tpm2-pkcs11) which is developed by the developers of the TPM2 Software Stack.

TPM2-PK11
==========

TPM2-PK11 provide a PKCS#11 backend for TPM 2.0 chips.
This allows you to use your TPM keys in every application which support the PKCS #11 standard.
For more information about howto setup keys, certificates and applications see the [wiki](https://github.com/irtimmer/tpm2-pk11/wiki).

## Features

- Sign and decrypt using private RSA key stored in TPM
- Provide on disk stored certificate in DER format to applications using PKCS #11

## Supported applications

- OpenSSH Client (SSH key in TPM)
- Firefox (Private key of Client certificate in TPM)
- GnuPG using [gnupg-pkcs11-scd](https://github.com/alonbl/gnupg-pkcs11-scd) (PGP key in TPM)

## Contribute

1. Fork us
2. Write code
3. Send Pull Requests
