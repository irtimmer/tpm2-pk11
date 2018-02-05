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

#define _GNU_SOURCE

#include "objects.h"
#include "certificate.h"
#include "tpm.h"
#include "pk11.h"

#include <stdio.h>
#include <endian.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#include <glob.h>

typedef struct userdata_tpm_t {
  TPM2B_PUBLIC tpm_key;
  TPM2B_NAME name;
  CK_UTF8CHAR label[256];
  PkcsObject public_object, private_object;
  PkcsKey key;
  PkcsPublicKey public_key;
  PkcsModulus modulus;
} UserdataTpm, *pUserdataTpm;

static AttrIndex OBJECT_INDEX[] = {
  attr_dynamic_index_of(CKA_ID, PkcsObject, id, id_size),
  attr_dynamic_index_of(CKA_LABEL, PkcsObject, label, label_size),
  attr_index_of(CKA_CLASS, PkcsObject, class)
};

static AttrIndex KEY_INDEX[] = {
  attr_index_of(CKA_SIGN, PkcsKey, sign),
  attr_index_of(CKA_DECRYPT, PkcsKey, decrypt),
  attr_index_of(CKA_KEY_TYPE, PkcsKey, key_type)
};

static AttrIndex PUBLIC_KEY_INDEX[] = {
  attr_index_of(CKA_PUBLIC_EXPONENT, PkcsPublicKey, exponent)
};

static AttrIndex MODULUS_INDEX[] = {
  attr_dynamic_index_of(CKA_MODULUS, PkcsModulus, modulus, modulus_size),
  attr_index_of(CKA_MODULUS_BITS, PkcsModulus, bits),
};

pObject object_get(pObjectList list, int id) {
  while (list != NULL) {
    if (list->object != NULL && list->object->id == id)
      return list->object;
    list = list->next;
  }
  return NULL;
}

void object_add(pObjectList list, pObject object) {
  if (list->object == NULL)
    list->object = object;
  else {
    pObjectList next = list->next;
    list->next = malloc(sizeof(ObjectList));
    list->next->object = object;
    list->next->next = next;
  }
}

void object_free(pObjectList list) {
  while (list != NULL) {
    pObjectList next = list->next;
    if (list->object != NULL) {
      pObject object = list->object;
      if (object->userdata != NULL)
        free(object->userdata);

      free(object->entries);
      free(object);
    }
    free(list);
    list = next;
  }
}

static inline int hex_to_char(int c)
{
    return c >= 10 ? c - 10 + 'A' : c + '0';
}

pObjectList object_load(TSS2_SYS_CONTEXT *ctx, struct config *config) {
  pObjectList list = malloc(sizeof(ObjectList));
  list->object = NULL;
  list->next = NULL;

  if (list == NULL)
    goto error;
  
  TPMS_CAPABILITY_DATA persistent;
  TPM2_RC rc = tpm_info(ctx, TPM2_HT_PERSISTENT, &persistent);
  if (rc != TPM2_RC_SUCCESS)
    goto error;

  for (int i = 0; i < persistent.data.handles.count; i++) {
    pUserdataTpm userdata = malloc(sizeof(UserdataTpm));
    if (userdata == NULL)
      goto error;

    memset(userdata, 0, sizeof(UserdataTpm));
    userdata->name.size = sizeof(TPMU_NAME);
    rc = tpm_readpublic(ctx, persistent.data.handles.handle[i], &userdata->tpm_key, &userdata->name);
    if (rc != TPM2_RC_SUCCESS) {
      free(userdata);
      goto error;
    }
    TPM2B_PUBLIC_KEY_RSA *rsa_key = &userdata->tpm_key.publicArea.unique.rsa;
    TPMS_RSA_PARMS *rsa_key_parms = &userdata->tpm_key.publicArea.parameters.rsaDetail;

    /*
     * fill the label with the same value as the name (they both have
     * different uses ; some application never display the id but only
     * the label). Since the label is an UTF8 string, we need to
     * transform the binary name into a hexadecimal string.
     */
    size_t max_label_size = userdata->name.size;
    if (max_label_size >= sizeof(userdata->label) / 2)
        max_label_size = sizeof(userdata->label) / 2;
    for (size_t n = 0; n < max_label_size; ++n) {
        userdata->label[2 * n + 0] = hex_to_char(userdata->name.name[n] >> 4);
        userdata->label[2 * n + 1] = hex_to_char(userdata->name.name[n] & 0x0f);
    }

    userdata->public_object.id = userdata->name.name;
    userdata->public_object.id_size = userdata->name.size;
    userdata->public_object.label = userdata->label;
    userdata->public_object.label_size = max_label_size * 2;
    userdata->public_object.class = CKO_PUBLIC_KEY;
    userdata->private_object.id = userdata->name.name;
    userdata->private_object.id_size = userdata->name.size;
    userdata->private_object.label = userdata->label;
    userdata->private_object.label_size = max_label_size * 2;
    userdata->private_object.class = CKO_PRIVATE_KEY;
    userdata->key.sign = CK_TRUE;
    userdata->key.decrypt = CK_TRUE;
    userdata->key.key_type = CKK_RSA;
    userdata->modulus.modulus = rsa_key->buffer;
    userdata->modulus.modulus_size = rsa_key_parms->keyBits / 8;
    userdata->modulus.bits = rsa_key_parms->keyBits;
    userdata->public_key.exponent = htobe32(rsa_key_parms->exponent == 0 ? 65537 : rsa_key_parms->exponent);

    pObject object = malloc(sizeof(Object));
    if (object == NULL) {
      free(userdata);
      goto error;
    }

    object->tpm_handle = 0;
    object->userdata = userdata;
    object->num_entries = 4;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->public_object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
    object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->public_key, PUBLIC_KEY_INDEX);
    object->entries[3] = (AttrIndexEntry) attr_index_entry(&userdata->modulus, MODULUS_INDEX);
    object_add(list, object);
    pObject public_object = object;

    object = malloc(sizeof(Object));
    if (object == NULL)
      goto error;

    object->tpm_handle = persistent.data.handles.handle[i];
    object->userdata = NULL;
    object->num_entries = 3;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
    object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->modulus, MODULUS_INDEX);
    object_add(list, object);

    public_object->opposite = object;
    object->opposite = public_object;
  }

  if (config->certificates) {
    glob_t results;
    char search_path[PATH_MAX];
    snprintf(search_path, PATH_MAX, "%s/*.der", config->certificates);
    if (glob(search_path, GLOB_TILDE, NULL, &results) == 0) {
      for (int i = 0; i < results.gl_pathc; i++) {
        pObject object = certificate_read(results.gl_pathv[i]);
        if (object)
          object_add(list, object);
      }
    }
  }

  return list;

error:
  object_free(list);
  return NULL;
}
