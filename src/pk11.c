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

#include "config.h"
#include "sessions.h"
#include "utils.h"
#include "tpm.h"
#include "object.h"

#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#define SLOT_ID 0x1234

#define get_session(x) ((struct session*) x)

static struct config pk11_config = {0};

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
  pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
  strncpy_pad(pInfo->manufacturerID, TPM2_PK11_MANUFACTURER, sizeof(pInfo->manufacturerID));
  strncpy_pad(pInfo->libraryDescription, TPM2_PK11_LIBRARY_DESCRIPTION, sizeof(pInfo->libraryDescription));
  pInfo->flags = 0;

  return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pusCount) {
  if (*pusCount && pSlotList)
    *pSlotList = SLOT_ID;

  *pusCount = 1;

  return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_RV  (*Notify) (CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication), CK_SESSION_HANDLE_PTR phSession) {
  *phSession = (unsigned long) malloc(sizeof(struct session));
  if ((void*) *phSession == NULL)
    return CKR_GENERAL_ERROR;

  int ret = session_init((struct session*) *phSession, &pk11_config);

  return ret != 0 ? CKR_GENERAL_ERROR : CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  session_close(get_session(hSession));
  free(get_session(hSession));
  return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  pInfo->slotID = 0;
  pInfo->state = CKS_RO_USER_FUNCTIONS;
  pInfo->flags = CKF_SERIAL_SESSION;
  pInfo->ulDeviceError = 0;
  return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  strncpy_pad(pInfo->manufacturerID, TPM2_PK11_MANUFACTURER, sizeof(pInfo->manufacturerID));
  strncpy_pad(pInfo->slotDescription, TPM2_PK11_SLOT_DESCRIPTION, sizeof(pInfo->slotDescription));

  pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;
  return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  strncpy_pad(pInfo->label, TPM2_PK11_LABEL, sizeof(pInfo->label));
  strncpy_pad(pInfo->manufacturerID, TPM2_PK11_MANUFACTURER, sizeof(pInfo->manufacturerID));
  strncpy_pad(pInfo->model, TPM2_PK11_MODEL, sizeof(pInfo->label));
  strncpy_pad(pInfo->serialNumber, TPM2_PK11_SERIAL, sizeof(pInfo->serialNumber));
  strncpy_pad(pInfo->utcTime, "", sizeof(pInfo->utcTime));

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
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;

  return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR filters, CK_ULONG nfilters) {
  struct session *session = get_session(hSession);
  session->find_cursor = session->objects;
  session->filters = filters;
  session->num_filters = nfilters;
  return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG usMaxObjectCount, CK_ULONG_PTR nfound) {
  TPMS_CAPABILITY_DATA persistent;
  tpm_list(get_session(hSession)->context, &persistent);
  struct session* session = get_session(hSession);
  *nfound = 0;

  while (session->find_cursor != NULL && *nfound < usMaxObjectCount) {
    pObject object = session->find_cursor->object;
    bool filtered = false;
    for (int j = 0; j < session->num_filters; j++) {
      size_t size = 0;
      void* value = attr_get(object, session->filters[j].type, &size);
      if (session->filters[j].ulValueLen != size || memcmp(session->filters[j].pValue, value, size) != 0) {
        filtered = true;
        break;
      }
    }
    if (!filtered) {
      phObject[*nfound] = (CK_OBJECT_HANDLE) session->find_cursor->object;
      (*nfound)++;
    }
    session->find_cursor = session->find_cursor->next;
  }

  return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount) {
  pObject object = (pObject) hObject;

  for (int i = 0; i < usCount; i++) {
    for (int j = 0; j < object->num_entries; j++) {
      void *obj = object->entries[j].object;
      pAttrIndex index = object->entries[j].indexes;
      for (int k = 0; k < object->entries[j].num_attrs; k++) {
        if (pTemplate[i].type == index[k].type) {
          if (index[k].size_offset == 0)
            retmem(pTemplate[i].pValue, &pTemplate[i].ulValueLen, obj + index[k].offset, index[k].size);
          else
            retmem(pTemplate[i].pValue, &pTemplate[i].ulValueLen, *((void**) (obj + index[k].offset)), *((size_t*) (obj + index[k].size_offset)));
        }
      }
    }
  }

  return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  pObject object = (pObject) hKey;
  get_session(hSession)->keyHandle = object->tpm_handle;
  get_session(hSession)->current_object = object;
  return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG usDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pusSignatureLen) {
  struct session* session = get_session(hSession);
  TPM2_RC ret;

  if (pk11_config.sign_using_encrypt) {
    TPM2B_PUBLIC_KEY_RSA message = { .size = TPM2_MAX_RSA_KEY_BYTES };
    pObject object = session->current_object->opposite;
    CK_ULONG_PTR key_size = (CK_ULONG_PTR) attr_get(object, CKA_MODULUS_BITS, NULL);
    ret = tpm_sign_encrypt(session->context, session->keyHandle, *key_size / 8, pData, usDataLen, &message);
    retmem(pSignature, pusSignatureLen, message.buffer, message.size);
  } else {
    TPMT_SIGNATURE signature = {0};
    ret = tpm_sign(session->context, session->keyHandle, pData, usDataLen, &signature);
    retmem(pSignature, pusSignatureLen, signature.signature.rsassa.sig.buffer, signature.signature.rsassa.sig.size);
  }

  return ret == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  pObject object = (pObject) hKey;
  get_session(hSession)->keyHandle = object->tpm_handle;
  return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  TPM2B_PUBLIC_KEY_RSA message = { .size = TPM2_MAX_RSA_KEY_BYTES };
  struct session* session = get_session(hSession);
  TPM2_RC ret = tpm_decrypt(session->context, session->keyHandle, pEncryptedData, ulEncryptedDataLen, &message);
  retmem(pData, pulDataLen, message.buffer, message.size);

  return ret == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  char configfile_path[256];
  snprintf(configfile_path, sizeof(configfile_path), "%s/" TPM2_PK11_CONFIG_DIR "/" TPM2_PK11_CONFIG_FILE, getenv("HOME"));
  if (config_load(configfile_path, &pk11_config) < 0)
    return CKR_GENERAL_ERROR;

  return CKR_OK;
}

/* Stubs for not yet supported functions*/
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken (CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG usPinLen, CK_CHAR_PTR pLabel) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG usPinLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_ULONG usOldLen, CK_CHAR_PTR pNewPin, CK_ULONG usNewLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_CloseAllSessions (CK_SLOT_ID slotID) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,  CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}


static CK_FUNCTION_LIST function_list = {
  { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
  .C_Initialize = C_Initialize,
  .C_Finalize = C_Finalize,
  .C_GetInfo = C_GetInfo,
  .C_GetSlotList = C_GetSlotList,
  .C_GetSlotInfo = C_GetSlotInfo,
  .C_GetTokenInfo = C_GetTokenInfo,
  .C_GetMechanismList = C_GetMechanismList,
  .C_GetMechanismInfo = C_GetMechanismInfo,
  .C_InitToken = C_InitToken,
  .C_InitPIN = C_InitPIN,
  .C_SetPIN = C_SetPIN,
  .C_OpenSession = C_OpenSession,
  .C_CloseSession = C_CloseSession,
  .C_CloseAllSessions = C_CloseAllSessions,
  .C_GetSessionInfo = C_GetSessionInfo,
  .C_CloseAllSessions = C_CloseAllSessions,
  .C_GetOperationState = C_GetOperationState,
  .C_SetOperationState = C_SetOperationState,
  .C_Login = C_Login,
  .C_Logout = C_Logout,
  .C_CreateObject = C_CreateObject,
  .C_CopyObject = C_CopyObject,
  .C_DestroyObject = C_DestroyObject,
  .C_GetObjectSize = C_GetObjectSize,
  .C_GetAttributeValue = C_GetAttributeValue,
  .C_SetAttributeValue = C_SetAttributeValue,
  .C_FindObjectsInit = C_FindObjectsInit,
  .C_FindObjects = C_FindObjects,
  .C_FindObjectsFinal = C_FindObjectsFinal,
  .C_EncryptInit = C_EncryptInit,
  .C_Encrypt = C_Encrypt,
  .C_EncryptUpdate = C_EncryptUpdate,
  .C_EncryptFinal = C_EncryptFinal,
  .C_DecryptInit = C_DecryptInit,
  .C_Decrypt = C_Decrypt,
  .C_DecryptUpdate = C_DecryptUpdate,
  .C_DecryptFinal = C_DecryptFinal,
  .C_DigestInit = C_DigestInit,
  .C_Digest = C_Digest,
  .C_DigestUpdate = C_DigestUpdate,
  .C_DigestKey = C_DigestKey,
  .C_DigestFinal = C_DigestFinal,
  .C_SignInit = C_SignInit,
  .C_Sign = C_Sign,
  .C_SignUpdate = C_SignUpdate,
  .C_SignFinal = C_SignFinal,
  .C_SignRecoverInit = C_SignRecoverInit,
  .C_SignRecover = C_SignRecover,
  .C_VerifyInit = C_VerifyInit,
  .C_Verify = C_Verify,
  .C_VerifyUpdate = C_VerifyUpdate,
  .C_VerifyFinal = C_VerifyFinal,
  .C_VerifyRecoverInit = C_VerifyRecoverInit,
  .C_VerifyRecover = C_VerifyRecover,
  .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
  .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
  .C_SignEncryptUpdate = C_SignEncryptUpdate,
  .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
  .C_GenerateKey = C_GenerateKey,
  .C_GenerateKeyPair = C_GenerateKeyPair,
  .C_WrapKey = C_WrapKey,
  .C_UnwrapKey = C_UnwrapKey,
  .C_DeriveKey = C_DeriveKey,
  .C_SeedRandom = C_SeedRandom,
  .C_GenerateRandom = C_GenerateRandom,
  .C_GetFunctionStatus = C_GetFunctionStatus,
  .C_CancelFunction = C_CancelFunction,
  .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  if (ppFunctionList == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  *ppFunctionList = &function_list;
  return CKR_OK;
}
