/*
 * Copyright (c) 2017-2018, Iwan Timmer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tpm20_compat.h"

TPM2_RC tpm_readpublic(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name);
TPM2_RC tpm_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature);
TPM2_RC tpm_decrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *cipher_text, unsigned long cipher_length, TPM2B_PUBLIC_KEY_RSA *message);
TPM2_RC tpm_sign_encrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, size_t key_size, unsigned char *message, size_t message_length, TPM2B_PUBLIC_KEY_RSA *signature);
TPM2_RC tpm_info(TSS2_SYS_CONTEXT *context, UINT32 property, TPMS_CAPABILITY_DATA* capability_data);
TPMS_TAGGED_PROPERTY* tpm_info_get(TPMS_TAGGED_PROPERTY properties[], size_t count, TPM2_PT key);
