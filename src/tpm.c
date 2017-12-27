/*
 * This file is part of tpm2-pk11.
 * Copyright (C) 2017 Iwan Timmer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "tpm.h"

#include <endian.h>

const unsigned char oid_sha1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
const unsigned char oid_sha256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }
#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

TPM2_RC tpm_readpublic(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name) {
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPM2B_NAME qualified_name = { .size = sizeof(TPMU_NAME) };

  return Tss2_Sys_ReadPublic(context, handle, 0, public, name, &qualified_name, &sessions_data_out);
}

TPM2_RC tpm_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature) {
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    .count = 1,
    .auths[0] = { .sessionHandle = TPM2_RS_PW },
  };

  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPMT_TK_HASHCHECK validation = {0};
  validation.tag = TPM2_ST_HASHCHECK;
  validation.hierarchy = TPM2_RH_NULL;

  TPMT_SIG_SCHEME scheme;
  scheme.scheme = TPM2_ALG_RSASSA;

  int digestSize;
  if (memcmp(hash, oid_sha1, sizeof(oid_sha1)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA1;
    digestSize = TPM2_SHA1_DIGEST_SIZE;
  } else if (memcmp(hash, oid_sha256, sizeof(oid_sha256)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
    digestSize = TPM2_SHA256_DIGEST_SIZE;
  } else
    return TPM2_RC_FAILURE;

  TPM2B_DIGEST digest = { .size = digestSize };
  // Remove OID from hash if provided
  memcpy(digest.buffer, hash - digestSize + hash_length, hash_length);

  return Tss2_Sys_Sign(context, handle, &sessions_data, &digest, &scheme, &validation, signature, &sessions_data_out);
}

TPM2_RC tpm_decrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *cipher_text, unsigned long cipher_length, TPM2B_PUBLIC_KEY_RSA *message) {
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    .count = 1,
    .auths[0] = { .sessionHandle = TPM2_RS_PW },
  };

  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPM2B_DATA label = {0};

  TPMT_RSA_DECRYPT scheme;
  scheme.scheme = TPM2_ALG_RSAES;

  TPM2B_PUBLIC_KEY_RSA cipher = { .size = cipher_length };
  memcpy(cipher.buffer, cipher_text, cipher_length);

  return Tss2_Sys_RSA_Decrypt(context, handle, &sessions_data, &cipher, &scheme, &label, message, &sessions_data_out);
}

TPM2_RC tpm_sign_encrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, size_t key_size, unsigned char *hash, size_t hash_length, TPM2B_PUBLIC_KEY_RSA *signature) {
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    .count = 1,
    .auths[0] = { .sessionHandle = TPM2_RS_PW },
  };

  TPM2B_PUBLIC_KEY_RSA message = { .size = key_size };
  unsigned char *p = message.buffer;

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

TPM2_RC tpm_list(TSS2_SYS_CONTEXT *context, TPMS_CAPABILITY_DATA* capability_data) {
  TPMI_YES_NO more_data;

  return Tss2_Sys_GetCapability(context, 0, TPM2_CAP_HANDLES, htobe32(TPM2_HT_PERSISTENT), TPM2_PT_TPM2_HR_PERSISTENT, &more_data, capability_data, 0);
}

TPM2_RC tpm_nvreadpublic(TSS2_SYS_CONTEXT *context, TPMI_RH_NV_INDEX index, TPM2B_NV_PUBLIC *nvpublic) {
  TPM2B_NAME nvname = TPM2B_TYPE_INIT(TPM2B_NAME, name);

  return Tss2_Sys_NV_ReadPublic(context, index, NULL, nvpublic, &nvname, NULL);
}

TPM2_RC tpm_nvlist(TSS2_SYS_CONTEXT *context, TPMS_CAPABILITY_DATA* capability_data) {
  TPMI_YES_NO moreData;

  return Tss2_Sys_GetCapability(context, 0, TPM2_CAP_HANDLES, htobe32(TPM2_HT_NV_INDEX), TPM2_PT_NV_INDEX_MAX, &moreData, capability_data, 0);
}

TPM2_RC tpm_nvread(TSS2_SYS_CONTEXT *context, TPMI_RH_NV_INDEX index, void *data, unsigned long *size) {
  if (!size)
    return TPM2_RC_FAILURE;

  TPM2B_NV_PUBLIC nvpublic = TPM2B_EMPTY_INIT;

  TPM2_RC rc = tpm_nvreadpublic(context, index, &nvpublic);
  if (rc != TPM2_RC_SUCCESS)
    return rc;
  if (*size <= nvpublic.nvPublic.dataSize) {
    *size = nvpublic.nvPublic.dataSize;
    return TPM2_RC_SIZE;
  }
  *size = nvpublic.nvPublic.dataSize;

  if (!data)
    return TPM2_RC_SUCCESS;

  TPM2B_MAX_NV_BUFFER nvdata = TPM2B_TYPE_INIT(TPM2B_MAX_NV_BUFFER, buffer);
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    .count = 1,
    .auths[0] = { .sessionHandle = TPM2_RS_PW },
  };
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  rc = Tss2_Sys_NV_Read(context, TPM2_RH_OWNER, index, &sessions_data, *size, 0, &nvdata, &sessions_data_out);
  if (rc == TPM2_RC_SUCCESS) {
    memcpy(data, &nvdata.buffer, nvdata.size);
  }
  return rc;
}
