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
#include "log.h"

#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <endian.h>

#define SLOT_ID 0x1234

#define get_session(x) ((struct session*) x)

static struct config pk11_config = {0};
static struct session main_session;

CK_RV C_GetInfo(CK_INFO_PTR info) {
  print_log(VERBOSE, "C_GetInfo");
  info->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
  info->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
  strncpy_pad(info->manufacturerID, sizeof(info->manufacturerID), TPM2_PK11_MANUFACTURER, sizeof(info->manufacturerID));
  strncpy_pad(info->libraryDescription, sizeof(info->libraryDescription), TPM2_PK11_LIBRARY_DESCRIPTION, sizeof(info->libraryDescription));
  info->flags = 0;

  return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL present, CK_SLOT_ID_PTR list, CK_ULONG_PTR count) {
  print_log(VERBOSE, "C_GetSlotList: present = %s", present ? "true" : "false");
  if (*count && list)
    *list = SLOT_ID;

  *count = 1;

  return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR application, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session) {
  print_log(VERBOSE, "C_OpenSession: id = %d, flags = %x", id, flags);
  *session = (unsigned long) malloc(sizeof(struct session));
  if ((void*) *session == NULL)
    return CKR_GENERAL_ERROR;

  int ret = session_init((struct session*) *session, &pk11_config);

  return ret != 0 ? CKR_GENERAL_ERROR : CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE session_handle) {
  print_log(VERBOSE, "C_CloseSession: session = %x", session_handle);
  session_close(get_session(session_handle));
  free(get_session(session_handle));
  return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session_handle, CK_SESSION_INFO_PTR info) {
  print_log(VERBOSE, "C_GetSessionInfo: session = %x", session_handle);
  info->slotID = 0;
  info->state = CKS_RO_USER_FUNCTIONS;
  info->flags = CKF_SERIAL_SESSION;
  info->ulDeviceError = 0;
  return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID id, CK_SLOT_INFO_PTR info) {
  print_log(VERBOSE, "C_GetSlotInfo: id = %d", id);
  TPMS_CAPABILITY_DATA fixed;
  if (tpm_info(main_session.context, TPM2_PT_FIXED, &fixed) != TPM2_RC_SUCCESS)
    return CKR_DEVICE_ERROR;

  TPML_TAGGED_TPM_PROPERTY props = fixed.data.tpmProperties;
  TPMS_TAGGED_PROPERTY* manufacturer = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_MANUFACTURER);
  UINT32 manufacturer_val = manufacturer ? htobe32(manufacturer->value) : 0;
  strncpy_pad(info->manufacturerID, sizeof(info->manufacturerID), manufacturer ? (char*) &manufacturer_val : TPM2_PK11_MANUFACTURER, manufacturer ? 4 : sizeof(info->manufacturerID));
  strncpy_pad(info->slotDescription, sizeof(info->slotDescription), TPM2_PK11_SLOT_DESCRIPTION, sizeof(info->slotDescription));

  info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
  TPMS_TAGGED_PROPERTY* revision = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_REVISION);
  info->hardwareVersion.major = revision ? revision->value / 100 : 0;
  info->hardwareVersion.minor = revision ? revision->value % 100 : 0;
  TPMS_TAGGED_PROPERTY* major = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_FIRMWARE_VERSION_1);
  info->firmwareVersion.major = major ? major->value : 0;
  TPMS_TAGGED_PROPERTY* minor = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_FIRMWARE_VERSION_2);
  info->firmwareVersion.minor = major ? major->value : 0;
  return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID id, CK_TOKEN_INFO_PTR info) {
  print_log(VERBOSE, "C_GetTokenInfo: id = %d", id);
  TPMS_CAPABILITY_DATA fixed;
  if (tpm_info(main_session.context, TPM2_PT_FIXED, &fixed) != TPM2_RC_SUCCESS)
    return CKR_DEVICE_ERROR;

  TPML_TAGGED_TPM_PROPERTY props = fixed.data.tpmProperties;
  strncpy_pad(info->label, sizeof(info->label), TPM2_PK11_EMPTY, sizeof(info->label));
  TPMS_TAGGED_PROPERTY* manufacturer = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_MANUFACTURER);
  UINT32 manufacturer_val = manufacturer ? htobe32(manufacturer->value) : 0;
  strncpy_pad(info->manufacturerID, sizeof(info->manufacturerID), manufacturer ? (char*) &manufacturer_val : TPM2_PK11_MANUFACTURER, manufacturer ? 4 : sizeof(info->manufacturerID));
  strncpy_pad(info->model, sizeof(info->label), TPM2_PK11_MODEL, sizeof(info->label));
  strncpy_pad(info->serialNumber, sizeof(info->serialNumber), TPM2_PK11_SERIAL, sizeof(info->serialNumber));
  strncpy_pad(info->utcTime, sizeof(info->utcTime), "", sizeof(info->utcTime));

  info->flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
  TPMS_TAGGED_PROPERTY* max_sessions = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_ACTIVE_SESSIONS_MAX);
  info->ulMaxSessionCount = max_sessions ? max_sessions->value : CK_EFFECTIVELY_INFINITE;
  info->ulSessionCount = open_sessions;
  info->ulMaxRwSessionCount = max_sessions ? max_sessions->value : CK_EFFECTIVELY_INFINITE;
  info->ulRwSessionCount = 0;
  info->ulMaxPinLen = 64;
  info->ulMinPinLen = 0;
  info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  TPMS_TAGGED_PROPERTY* revision = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_REVISION);
  info->hardwareVersion.major = revision ? revision->value / 100 : 0;
  info->hardwareVersion.minor = revision ? revision->value % 100 : 0;
  TPMS_TAGGED_PROPERTY* major = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_FIRMWARE_VERSION_1);
  info->firmwareVersion.major = major ? major->value : 0;
  TPMS_TAGGED_PROPERTY* minor = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_FIRMWARE_VERSION_2);
  info->firmwareVersion.minor = major ? major->value : 0;

  return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR reserved) {
  print_log(VERBOSE, "C_Finalize");
  session_close(&main_session);
  return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session_handle, CK_ATTRIBUTE_PTR filters, CK_ULONG count) {
  print_log(VERBOSE, "C_FindObjectsInit: session = %x, count = %d", session_handle, count);
  struct session *session = get_session(session_handle);
  session->find_cursor = session->objects;
  session->filters = filters;
  session->num_filters = count;
  return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE_PTR object_handle, CK_ULONG max_objects, CK_ULONG_PTR found) {
  print_log(VERBOSE, "C_FindObjects: session = %x, max = %d", session_handle, max_objects);
  TPMS_CAPABILITY_DATA persistent;
  tpm_info(get_session(session_handle)->context, TPM2_HT_PERSISTENT, &persistent);
  struct session* session = get_session(session_handle);
  *found = 0;

  while (session->find_cursor != NULL && *found < max_objects) {
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
      object_handle[*found] = (CK_OBJECT_HANDLE) session->find_cursor->object;
      (*found)++;
    }
    session->find_cursor = session->find_cursor->next;
  }

  return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session_handle) {
  print_log(VERBOSE, "C_FindObjectsFinal: session = %x", session_handle);
  return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object_handle, CK_ATTRIBUTE_PTR template, CK_ULONG count) {
  print_log(VERBOSE, "C_GetAttributeValue: session = %x, object = %x, count = %d", session_handle, object_handle, count);
  pObject object = (pObject) object_handle;

  for (int i = 0; i < count; i++) {
    void* entry_obj = NULL;
    pAttrIndex entry = NULL;
    for (int j = 0; j < object->num_entries; j++) {
      void *obj = object->entries[j].object;
      pAttrIndex index = object->entries[j].indexes;
      for (int k = 0; k < object->entries[j].num_attrs; k++) {
        if (template[i].type == index[k].type) {
          entry = &index[k];
          entry_obj = obj;
          continue;
        }
      }
      if (entry)
        continue;
    }
    if (!entry) {
      print_log(DEBUG, " attribute not found: type = %x", template[i].type);
      template[i].ulValueLen = 0;
    } else if (entry->size_offset == 0) {
      print_log(DEBUG, " return attribute: type = %x, size = %d, buffer_size = %d", template[i].type, entry->size, template[i].ulValueLen);
      retmem(template[i].pValue, &template[i].ulValueLen, entry_obj + entry->offset, entry->size);
    } else {
      print_log(DEBUG, " return attribute: type = %x, size = %d, buffer_size = %d", template[i].type, *((size_t*) (entry_obj + entry->size_offset)), template[i].ulValueLen);
      retmem(template[i].pValue, &template[i].ulValueLen, *((void**) (entry_obj + entry->offset)), *((size_t*) (entry_obj + entry->size_offset)));
    }
  }

  return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  print_log(VERBOSE, "C_SignInit: session = %x, key = %x", session_handle, key);
  pObject object = (pObject) key;
  struct session* session = get_session(session_handle);
  session->key_handle = object->tpm_handle;
  session->current_object = object;
  return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
  print_log(VERBOSE, "C_Sign: session = %x, len = %d", session_handle, data_len);
  struct session* session = get_session(session_handle);
  TPM2_RC ret;

  if (pk11_config.sign_using_encrypt) {
    TPM2B_PUBLIC_KEY_RSA message = { .size = TPM2_MAX_RSA_KEY_BYTES };
    pObject object = session->current_object->opposite;
    CK_ULONG_PTR key_size = (CK_ULONG_PTR) attr_get(object, CKA_MODULUS_BITS, NULL);
    ret = tpm_sign_encrypt(session->context, session->key_handle, *key_size / 8, data, data_len, &message);
    retmem(signature, signature_len, message.buffer, message.size);
  } else {
    TPMT_SIGNATURE sign = {0};
    ret = tpm_sign(session->context, session->key_handle, data, data_len, &sign);
    retmem(signature, signature_len, sign.signature.rsassa.sig.buffer, sign.signature.rsassa.sig.size);
  }

  return ret == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  print_log(VERBOSE, "C_DecryptInit: session = %x, key = %x", session_handle, key);
  pObject object = (pObject) key;
  get_session(session_handle)->key_handle = object->tpm_handle;
  return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR enc_data, CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
  print_log(VERBOSE, "C_Decrypt: session = %x, len = %d", session_handle, enc_data_len);
  TPM2B_PUBLIC_KEY_RSA message = { .size = TPM2_MAX_RSA_KEY_BYTES };
  struct session* session = get_session(session_handle);
  TPM2_RC ret = tpm_decrypt(session->context, session->key_handle, enc_data, enc_data_len, &message);
  retmem(data, data_len, message.buffer, message.size);

  return ret == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  print_log(VERBOSE, "C_Initialize");
  char configfile_path[256];
  snprintf(configfile_path, sizeof(configfile_path), "%s/" TPM2_PK11_CONFIG_DIR "/" TPM2_PK11_CONFIG_FILE, getenv("HOME"));
  if (config_load(configfile_path, &pk11_config) < 0)
    return CKR_GENERAL_ERROR;

  session_init(&main_session, &pk11_config);
  log_init(pk11_config.log_file, pk11_config.log_level);
  return CKR_OK;
}

/* Stubs for not yet supported functions*/
CK_RV C_GetMechanismList(CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
  print_log(VERBOSE, "C_GetMechanismList: slot = %d", id);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo (CK_SLOT_ID id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info) {
  print_log(VERBOSE, "C_GetMechanismInfo: slot = %d", id);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken (CK_SLOT_ID id, CK_CHAR_PTR pin, CK_ULONG pin_len, CK_CHAR_PTR label) {
  print_log(VERBOSE, "C_InitToken: slot = %d", id);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN (CK_SESSION_HANDLE session_handle, CK_CHAR_PTR pin, CK_ULONG pin_len) {
  print_log(VERBOSE, "C_InitPIN: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN (CK_SESSION_HANDLE session_handle, CK_CHAR_PTR old_pin, CK_ULONG old_pin_len, CK_CHAR_PTR new_pin, CK_ULONG new_pin_len) {
  print_log(VERBOSE, "C_SetPIN: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_CloseAllSessions (CK_SLOT_ID id) {
  print_log(VERBOSE, "C_CloseAllSessions: slot = %d", id);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR state, CK_ULONG_PTR state_len) {
  print_log(VERBOSE, "C_GetOperationState: session = %x, len = %d", session_handle, state_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR state, CK_ULONG state_len, CK_OBJECT_HANDLE enc_key, CK_OBJECT_HANDLE auth_key) {
  print_log(VERBOSE, "C_SetOperationState: session = %x, len = %d, enc_key = %x, auth_key = %x", session_handle, state_len, enc_key, auth_key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE session_handle, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) {
  print_log(VERBOSE, "C_Login: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE session_handle) {
  print_log(VERBOSE, "C_Logout: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE session_handle, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR object) {
  print_log(VERBOSE, "C_CreateObject: session = %x, count = %d", session_handle, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object) {
  print_log(VERBOSE, "C_CopyObject: session = %x, object = %x, count = %d", session_handle, object, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object) {
  print_log(VERBOSE, "C_DestroyObject: session = %x, object = %x", session_handle, object);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object, CK_ULONG_PTR size) {
  print_log(VERBOSE, "C_GetObjectSize: session = %x, object = %x", session_handle, object);
  return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_SetAttributeValue(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count) {
  print_log(VERBOSE, "C_SetAttributeValue: session = %x, object = %x, count = %d", session_handle, object, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE object) {
  print_log(VERBOSE, "C_EncryptInit: session = %x, object = %x", session_handle, object);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR enc_data, CK_ULONG_PTR enc_data_len) {
  print_log(VERBOSE, "C_Encrypt: session = %x, len = %x", session_handle, data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR enc_data, CK_ULONG_PTR enc_data_len) {
  print_log(VERBOSE, "C_EncryptUpdate: session = %x, len = %x", session_handle, data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR enc_data, CK_ULONG_PTR enc_data_len) {
  print_log(VERBOSE, "C_EncryptFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR enc_data, CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
  print_log(VERBOSE, "C_DecryptUpdate: session = %x, len = %x", session_handle, enc_data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
  print_log(VERBOSE, "C_DecryptFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism) {
  print_log(VERBOSE, "C_DigestInit: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {
  print_log(VERBOSE, "C_Digest: session = %x, len = %x", session_handle, data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len) {
  print_log(VERBOSE, "C_DigestUpdate: session = %x, len = %x", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object) {
  print_log(VERBOSE, "C_DigestKey: session = %x, object = %x", session_handle, object);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {
  print_log(VERBOSE, "C_DigestFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len) {
  print_log(VERBOSE, "C_SignUpdate: session = %x, len = %x", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
  print_log(VERBOSE, "C_SignFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  print_log(VERBOSE, "C_SignRecoverInit: session = %x, key = %x", session_handle, key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
  print_log(VERBOSE, "C_SignRecover: session = %x, len = %d", session_handle, data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  print_log(VERBOSE, "C_VerifyInit: session = %x, key = %x", session_handle, key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len) {
  print_log(VERBOSE, "C_Verify: session = %x, len = %d", session_handle, data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len) {
  print_log(VERBOSE, "C_VerifyUpdate: session = %x, len = %d", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR signature, CK_ULONG signature_len) {
  print_log(VERBOSE, "C_VerifyFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  print_log(VERBOSE, "C_VerifyRecoverInit: session = %x, key = %x", session_handle, key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR signature, CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
  print_log(VERBOSE, "C_VerifyRecover: session = %x, len = %d", session_handle, signature_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc_part, CK_ULONG_PTR enc_part_len) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR dec_part, CK_ULONG_PTR dec_part_len) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc_part, CK_ULONG_PTR enc_part_len) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR enc_part, CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", session_handle, enc_part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
  print_log(VERBOSE, "C_GenerateKey: session = %x, count = %d", session_handle, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR public_key_template, CK_ULONG public_key_attr_count, CK_ATTRIBUTE_PTR private_key_template, CK_ULONG private_key_attr_count, CK_OBJECT_HANDLE_PTR public_key, CK_OBJECT_HANDLE_PTR private_key) {
  print_log(VERBOSE, "C_GenerateKeyPair: session = %x, public_count = %d, private_count = %d", session_handle, public_key_attr_count, private_key_attr_count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len) {
  print_log(VERBOSE, "C_WrapKey: session = %x, wrapping_key = %x, key = %x", session_handle, wrapping_key, key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
  print_log(VERBOSE, "C_UnwrapKey: session = %x, unwrapping_key = %x, key = %x, count = %d", session_handle, unwrapping_key, key, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
  print_log(VERBOSE, "C_WrapKey: session = %x, base_key = %x, count = %d", session_handle, base_key, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR seed, CK_ULONG seed_len) {
  print_log(VERBOSE, "C_SeedRandom: session = %x, len = %d", session_handle, seed_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR random_data, CK_ULONG random_data_len) {
  print_log(VERBOSE, "C_GenerateRandom: session = %x, len = %d", session_handle, random_data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE session_handle) {
  print_log(VERBOSE, "C_GetFunctionStatus: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE session_handle) {
  print_log(VERBOSE, "C_CancelFunction: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved) {
  print_log(VERBOSE, "C_WaitForSlotEvent: flags = %x", flags);
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

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list) {
  if (list == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  *list = &function_list;
  return CKR_OK;
}
