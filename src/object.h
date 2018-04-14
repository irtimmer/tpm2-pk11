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

#pragma once

#include "tpm20_compat.h"

#include <stddef.h>

#include <p11-kit/pkcs11.h>

#define NELEMS(x) (sizeof(x) / sizeof((x)[0]))

#define attr_index_of(type, struct, attribute) {type, offsetof(struct, attribute), sizeof(((struct*)0)->attribute), 0}
#define attr_dynamic_index_of(type, struct, attribute, size_attribute) {type, offsetof(struct, attribute), 0, offsetof(struct, size_attribute)}
#define attr_index_entry(object, index) {object, index, NELEMS(index)}

typedef struct attr_index_t {
  CK_ATTRIBUTE_TYPE type;
  size_t offset;
  size_t size;
  size_t size_offset;
} AttrIndex, *pAttrIndex;

typedef struct attr_index_entry_t {
  void* object;
  pAttrIndex indexes;
  size_t num_attrs;
} AttrIndexEntry, *pAttrIndexEntry;

typedef struct attr_map_t {
  CK_ATTRIBUTE_TYPE type;
  unsigned int len;
  void* value;
  struct attr_map_t* next;
} AttrMap, *pAttrMap;

typedef struct object_t {
  int id;
  void* userdata;
  pAttrIndexEntry entries;
  size_t num_entries;
  TPMI_DH_OBJECT tpm_handle;
  struct object_t *opposite;
} Object, *pObject;

typedef struct pkcs_object_t {
  void* id;
  size_t id_size;
  char* label;
  size_t label_size;
  CK_OBJECT_CLASS class;
  CK_BBOOL token;
} PkcsObject, *pPkcsObject;

typedef struct pkcs_key_t {
  CK_BBOOL sign;
  CK_BBOOL decrypt;
  CK_KEY_TYPE key_type;
} PkcsKey, *pPkcsKey;

typedef struct pkcs_public_key_t {
  uint32_t exponent;
} PkcsPublicKey, *pPkcsPublicKey;

typedef struct pkcs_modulus_t {
  void* modulus;
  size_t modulus_size;
  CK_ULONG bits;
} PkcsModulus, *pPkcsModulus;

typedef struct pkcs_x509_t {
  char* value;
  size_t value_size;
  char* subject;
  size_t subject_size;
  char* issuer;
  size_t issuer_size;
  char* serial;
  size_t serial_size;
  CK_CERTIFICATE_TYPE cert_type;
} PkcsX509, *pPkcsX509;

extern AttrIndex OBJECT_INDEX[4];
extern AttrIndex KEY_INDEX[3];
extern AttrIndex PUBLIC_KEY_INDEX[1];
extern AttrIndex MODULUS_INDEX[2];
extern AttrIndex CERTIFICATE_INDEX[5];

void* attr_get(pObject object, CK_ATTRIBUTE_TYPE type, size_t *size);
