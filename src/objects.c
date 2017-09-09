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

#include "objects.h"
#include "tpm.h"
#include "pk11.h"

#include <endian.h>

#define NELEMS(x) (sizeof(x) / sizeof((x)[0]))

typedef struct userdata_tpm_t {
  TPM2B_PUBLIC tpm_key;
  TPM2B_NAME name;
  PkcsObject object;
  PkcsKey key;
  PkcsPublicKey public_key;
} UserdataTpm, *pUserdataTpm;

static AttrIndex OBJECT_INDEX[] = {
  attr_dynamic_index_of(CKA_ID, PkcsObject, id, id_size),
  attr_index_of(CKA_CLASS, PkcsObject, class)
};

static AttrIndex KEY_INDEX[] = {
  attr_index_of(CKA_SIGN, PkcsKey, sign),
  attr_index_of(CKA_DECRYPT, PkcsKey, decrypt),
  attr_index_of(CKA_KEY_TYPE, PkcsKey, key_type)
};

static AttrIndex PUBLIC_KEY_INDEX[] = {
  attr_dynamic_index_of(CKA_MODULUS, PkcsPublicKey, modulus, modulus_size),
  attr_index_of(CKA_MODULUS_BITS, PkcsPublicKey, bits),
  attr_index_of(CKA_PUBLIC_EXPONENT, PkcsPublicKey, exponent)
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

pObjectList object_load(TSS2_SYS_CONTEXT *ctx) {
  pObjectList list = malloc(sizeof(ObjectList));
  list->object = NULL;
  list->next = NULL;

  if (list == NULL)
    goto error;
  
  TPMS_CAPABILITY_DATA persistent;
  tpm_list(ctx, &persistent);
  for (int i = 0; i < persistent.data.handles.count; i++) {
    pUserdataTpm userdata = malloc(sizeof(UserdataTpm));
    if (userdata == NULL) {
      free(userdata);
      goto error;
    }

    memset(userdata, 0, sizeof(UserdataTpm));
    userdata->name.t.size = sizeof(TPMU_NAME);
    tpm_readpublic(ctx, persistent.data.handles.handle[i], &userdata->tpm_key, &userdata->name);
    TPM2B_PUBLIC_KEY_RSA *rsa_key = &userdata->tpm_key.t.publicArea.unique.rsa;
    TPMS_RSA_PARMS *rsa_key_parms = &userdata->tpm_key.t.publicArea.parameters.rsaDetail;

    userdata->object.id = userdata->name.t.name;
    userdata->object.id_size = userdata->name.t.size;
    userdata->object.class = CKO_PUBLIC_KEY;
    userdata->key.sign = CK_TRUE;
    userdata->key.decrypt = CK_TRUE;
    userdata->key.key_type = CKK_RSA;
    userdata->public_key.modulus = rsa_key->b.buffer;
    userdata->public_key.modulus_size = rsa_key_parms->keyBits / 8;
    userdata->public_key.bits = rsa_key_parms->keyBits;
    userdata->public_key.exponent = htobe32(rsa_key_parms->exponent == 0 ? 65537 : rsa_key_parms->exponent);

    pObject object = malloc(sizeof(Object));
    if (object == NULL)
      goto error;

    object->userdata = userdata;
    object->num_entries = 3;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
    object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->public_key, PUBLIC_KEY_INDEX);
    object_add(list, object);
  }

  return list;

error:
  object_free(list);
  return NULL;
}
