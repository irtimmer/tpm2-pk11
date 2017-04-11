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

TPM_RC tpm_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hashLength, TPMT_SIGNATURE *signature) {
  TPMS_AUTH_COMMAND sessionData;
  sessionData.hmac.t.size = 0;
  *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;
  sessionData.sessionHandle = TPM_RS_PW;
  sessionData.nonce.t.size = 0;
  
  TPMS_AUTH_RESPONSE sessionDataOut;

  TPMT_TK_HASHCHECK validation = {0};
  validation.tag = TPM_ST_HASHCHECK;
  validation.hierarchy = TPM_RH_NULL;

  TPMS_AUTH_COMMAND *sessionDataArray[1];
  TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
  sessionDataArray[0] = &sessionData;
  sessionDataOutArray[0] = &sessionDataOut;
  
  TSS2_SYS_CMD_AUTHS sessionsData;
  sessionsData.cmdAuths = &sessionDataArray[0];
  sessionsData.cmdAuthsCount = 1;

  TSS2_SYS_RSP_AUTHS sessionsDataOut;
  sessionsDataOut.rspAuths = &sessionDataOutArray[0];
  sessionsDataOut.rspAuthsCount = 1;

  TPMT_SIG_SCHEME scheme;
  scheme.scheme = TPM_ALG_RSASSA;
  scheme.details.rsassa.hashAlg = TPM_ALG_SHA1;

  TPM2B_DIGEST digest = {0};
  digest.t.size = digest.b.size = SHA1_DIGEST_SIZE;
  // Remove OID from hash if provided
  memcpy(digest.t.buffer, hash - SHA1_DIGEST_SIZE + hashLength, hashLength);

  return Tss2_Sys_Sign(context, handle, &sessionsData, &digest, &scheme, &validation, signature, &sessionsDataOut);
}
