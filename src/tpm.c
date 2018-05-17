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

#include "tpm.h"

#include <string.h>
#include <endian.h>

const unsigned char oid_sha1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
const unsigned char oid_sha256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
const unsigned char oid_sha384[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,0x00, 0x04, 0x30};
const unsigned char oid_sha512[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,0x00, 0x04, 0x40};

static void tpm_set_session_password(TSS2L_SYS_AUTH_COMMAND *sessions_data, char *password) {
  TPMS_AUTH_COMMAND *cmd = sessions_data->cmdAuths[0];
  strncat(cmd->hmac.t.buffer, password, sizeof(TPMU_HA));
  cmd->hmac.t.size = strlen(password) >= sizeof(TPMU_HA) ? 0 : strlen(password);
}

TPM2_RC tpm_readpublic(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name) {
  TSS_COMPAT_AUTH_RESPONSE_BEGIN;
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = TSS_COMPAT_AUTH_RESPONSE_VALUE;

  TPM2B_NAME qualified_name = { .TSS_COMPAT_TMPB(size) = sizeof(TPMU_NAME) };

  return Tss2_Sys_ReadPublic(context, handle, 0, public, name, &qualified_name, &sessions_data_out);
}

TPM2_RC tpm_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature, char *password) {
  TSS_COMPAT_AUTH_COMMAND_BEGIN(TPM2_RS_PW);
  TSS2L_SYS_AUTH_COMMAND sessions_data = TSS_COMPAT_AUTH_COMMAND_VALUE(TPM2_RS_PW);
  if (password)
    tpm_set_session_password(&sessions_data, password);

  TSS_COMPAT_AUTH_RESPONSE_BEGIN;
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = TSS_COMPAT_AUTH_RESPONSE_VALUE;

  TPMT_TK_HASHCHECK validation = {0};
  validation.tag = TPM2_ST_HASHCHECK;
  validation.hierarchy = TPM2_RH_NULL;

  TPMT_SIG_SCHEME scheme;
  scheme.scheme = TPM2_ALG_RSASSA;

  int digest_size;
  if (sizeof(oid_sha1) < hash_length && memcmp(hash, oid_sha1, sizeof(oid_sha1)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA1;
    digest_size = TPM2_SHA1_DIGEST_SIZE;
  } else if (sizeof(oid_sha256) < hash_length && memcmp(hash, oid_sha256, sizeof(oid_sha256)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
    digest_size = TPM2_SHA256_DIGEST_SIZE;
  } else if (sizeof(oid_sha384) < hash_length && memcmp(hash, oid_sha384, sizeof(oid_sha384)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA384;
    digest_size = TPM2_SHA384_DIGEST_SIZE;
  } else if (sizeof(oid_sha512) < hash_length && memcmp(hash, oid_sha512, sizeof(oid_sha512)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA512;
    digest_size = TPM2_SHA512_DIGEST_SIZE;
  } else
    return TPM2_RC_FAILURE;

  TPM2B_DIGEST digest = { .TSS_COMPAT_TMPB(size) = digest_size };
  // Remove OID from hash if provided
  memcpy(digest.TSS_COMPAT_TMPB(buffer), hash - digest_size + hash_length, digest_size);

  return Tss2_Sys_Sign(context, handle, &sessions_data, &digest, &scheme, &validation, signature, &sessions_data_out);
}

TPM2_RC tpm_decrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *cipher_text, unsigned long cipher_length, TPM2B_PUBLIC_KEY_RSA *message, char *password) {
  TSS_COMPAT_AUTH_COMMAND_BEGIN(TPM2_RS_PW);
  TSS2L_SYS_AUTH_COMMAND sessions_data = TSS_COMPAT_AUTH_COMMAND_VALUE(TPM2_RS_PW);
  if (password)
    tpm_set_session_password(&sessions_data, password);

  TSS_COMPAT_AUTH_RESPONSE_BEGIN;
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = TSS_COMPAT_AUTH_RESPONSE_VALUE;

  TPM2B_DATA label = {0};

  TPMT_RSA_DECRYPT scheme;
  scheme.scheme = TPM2_ALG_RSAES;

  TPM2B_PUBLIC_KEY_RSA cipher = { .TSS_COMPAT_TMPB(size) = cipher_length };
  memcpy(cipher.TSS_COMPAT_TMPB(buffer), cipher_text, cipher_length);

  return Tss2_Sys_RSA_Decrypt(context, handle, &sessions_data, &cipher, &scheme, &label, message, &sessions_data_out);
}

TPM2_RC tpm_sign_encrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, size_t key_size, unsigned char *hash, size_t hash_length, TPM2B_PUBLIC_KEY_RSA *signature, char *password) {
  TSS_COMPAT_AUTH_COMMAND_BEGIN(TPM2_RS_PW);
  TSS2L_SYS_AUTH_COMMAND sessions_data = TSS_COMPAT_AUTH_COMMAND_VALUE(TPM2_RS_PW);
  if (password)
    tpm_set_session_password(&sessions_data, password);

  TPM2B_PUBLIC_KEY_RSA message = { .TSS_COMPAT_TMPB(size) = key_size };
  unsigned char *p = message.TSS_COMPAT_TMPB(buffer);

  *p++ = 0;
  *p++ = 1;
  size_t nb_pad = key_size - hash_length - 3;
  memset(p, 0xFF, nb_pad);
  p += nb_pad;
  *p++ = 0;
  memcpy(p, hash, hash_length);

  TPM2B_DATA label = {0};
  TPMT_RSA_DECRYPT scheme = { .scheme = TPM2_ALG_NULL };

  return Tss2_Sys_RSA_Decrypt(context, handle, &sessions_data, &message, &scheme, &label, signature, NULL);
}

TPM2_RC tpm_info(TSS2_SYS_CONTEXT *context, UINT32 property, TPMS_CAPABILITY_DATA* capability_data) {
  TPMI_YES_NO more_data;
  TPM2_CAP capability;
  UINT32 propertyCount;

  switch (property) {
    case TPM2_HT_PERSISTENT:
      property = htobe32(property);
      capability = TPM2_CAP_HANDLES;
      propertyCount = TPM2_PT_TPM2_HR_PERSISTENT;
      break;
    case TPM2_PT_FIXED:
      capability = TPM2_CAP_TPM_PROPERTIES;
      propertyCount = TPM2_MAX_TPM_PROPERTIES;
      break;
  }
  
  return Tss2_Sys_GetCapability(context, 0, capability, property, propertyCount, &more_data, capability_data, 0);
}

TPMS_TAGGED_PROPERTY* tpm_info_get(TPMS_TAGGED_PROPERTY properties[], size_t count, TPM2_PT key) {
  for (int i = 0; i < count; i++) {
    if (properties[i].property == key)
      return &properties[i];

  }

  return NULL;
}
