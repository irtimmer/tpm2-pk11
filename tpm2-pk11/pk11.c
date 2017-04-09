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

#include "pk11.h"

#include "sessions.h"
#include "utils.h"

#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <p11-kit/pkcs11.h>

#define SLOT_ID 0x1234

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  memset(pInfo, 0, sizeof(CK_INFO));
  pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
  pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
  strncpy(pInfo->manufacturerID, TPM2_PK11_MANUFACTURER, sizeof(pInfo->manufacturerID));
  strncpy(pInfo->libraryDescription, TPM2_PK11_LIBRARY, sizeof(pInfo->libraryDescription));

  return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pusCount) {
  if (*pusCount)
    *pSlotList = SLOT_ID;

  *pusCount = 1;

  return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_RV  (*Notify) (CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication), CK_SESSION_HANDLE_PTR phSession) {
  *phSession = session_open();

  return *phSession == -1 ? CKR_GENERAL_ERROR : CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  strncpy(pInfo->label, "TPM2-PK11",sizeof(pInfo->label));
  strncpy(pInfo->manufacturerID, TPM2_PK11_MANUFACTURER, sizeof(pInfo->manufacturerID));
  strncpy(pInfo->model, TPM2_PK11_MODEL, sizeof(pInfo->model));
  strncpy(pInfo->serialNumber, TPM2_PK11_SERIAL, sizeof(pInfo->serialNumber));
  strncpy(pInfo->utcTime, "", sizeof(pInfo->utcTime));

  pInfo->flags = CKF_TOKEN_INITIALIZED;
  pInfo->ulMaxSessionCount = 1;
  pInfo->ulSessionCount = 0;
  pInfo->ulMaxRwSessionCount = 1;
  pInfo->ulRwSessionCount = 0;
  pInfo->ulMaxPinLen = 64;
  pInfo->ulMinPinLen = 8;
  pInfo->ulTotalPublicMemory = 8;
  pInfo->ulFreePublicMemory = 8;
  pInfo->ulTotalPrivateMemory = 8;
  pInfo->ulFreePrivateMemory = 8;
  pInfo->hardwareVersion.major = 0;
  pInfo->firmwareVersion.major = 0;

  return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR filters, CK_ULONG nfilters) {
  sessions[hSession].findPosition = 0;
  return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG usMaxObjectCount, CK_ULONG_PTR nfound) {
  if (usMaxObjectCount == 0 || sessions[hSession].findPosition >= 1)
    *nfound = 0;
  else {
    *nfound = 1;
    sessions[hSession].findPosition++;
  }
  return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount) {
  size_t length;
  TPM2B_PUBLIC *key = map_file(KEY_PUBLIC_FILE, &length);
  if (length == 0)
    return CKR_GENERAL_ERROR;

  TPM2B_PUBLIC_KEY_RSA *rsa_key = &key->t.publicArea.unique.rsa;
  TPMS_RSA_PARMS *rsa_key_parms = &key->t.publicArea.parameters.rsaDetail;
  uint32_t exponent = htonl(rsa_key_parms->exponent == 0 ? 65537 : rsa_key_parms->exponent);

  for (int i = 0; i < usCount; i++) {
    switch (pTemplate[i].type) {
    case CKA_ID:
      pTemplate[i].ulValueLen = 8;

      break;
    case CKA_PUBLIC_EXPONENT:
      pTemplate[i].ulValueLen = sizeof(uint32_t);
      if (pTemplate[i].pValue)
        memcpy(pTemplate[i].pValue, &exponent, sizeof(uint32_t));

      break;
    case CKA_MODULUS:
      pTemplate[i].ulValueLen = rsa_key_parms->keyBits / 8;
      if (pTemplate[i].pValue)
        memcpy(pTemplate[i].pValue, rsa_key->b.buffer, pTemplate[i].ulValueLen);

      break;
    default:
      pTemplate[i].ulValueLen = 0;
    }
  }

  munmap(key, length);
  return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG usDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pusSignatureLen) {
  return CKR_OK;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  return CKR_OK;
}

static CK_FUNCTION_LIST function_list = {
  { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
  .C_Initialize = C_Initialize,
  .C_Finalize = C_Finalize,
  .C_GetInfo = C_GetInfo,
  .C_GetSlotList = C_GetSlotList,
  .C_GetSlotInfo = C_GetSlotInfo,
  .C_GetTokenInfo = C_GetTokenInfo,
  .C_OpenSession = C_OpenSession,
  .C_GetAttributeValue = C_GetAttributeValue,
  .C_FindObjectsInit = C_FindObjectsInit,
  .C_FindObjects = C_FindObjects,
  .C_FindObjectsFinal = C_FindObjectsFinal,
  .C_SignInit = C_SignInit,
  .C_Sign = C_Sign
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  if (ppFunctionList == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  *ppFunctionList = &function_list;
  return CKR_OK;
}
