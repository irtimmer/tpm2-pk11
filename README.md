TPM2-PK11
==========

[![Build Status](https://travis-ci.org/irtimmer/tpm2-pk11.svg?branch=master)](https://travis-ci.org/irtimmer/tpm2-pk11)

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

## Build & Install

CMake and Make libraries are needed for (pre-)compilation and building.
They can be installed with the following command:

`apt-get install cmake make`

1. Check out the Git repository `git clone https://github.com/irtimmer/tpm2-pk11.git`
2. Change into project directiory `cd tpm2-pk11/`
3. Create build directory `mkdir build`
4. Change into build directory `cd build/`
5. Execute CMake `cmake ..`
6. Execute Make `make`

## Contribute

1. Fork us
2. Write code
3. Send Pull Requests
