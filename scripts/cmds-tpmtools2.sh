#!/bin/sh
#This command was tested on a Ubuntu 18.04 using the in-kernel Resouce Manage
#To run this commands, you need tpm-tools 2.1. This script is not compatible with newer tpm-tools.
#Hardware used was a Dell XPS 9360

export TPM2TOOLS_TCTI_NAME=device
export TPM2TOOLS_DEVICE_FILE=/dev/tpmrm0

set -ex

cd ~/.tpm2
tpm2_createprimary -A e -g 0x000b -G 0x0001 -C po.ctx
#note, you may need to set additional object attributes to make it work with your specific application
tpm2_create -c po.ctx -g 0x000b -G 0x0001 -o key.pub -O key.priv
tpm2_load -c po.ctx -u key.pub -r key.priv -n key.name -C obj.ctx
tpm2_evictcontrol -A o -c obj.ctx -S 0x81010011
rm key.name *.ctx
rm key.priv #TPM now controls private key

