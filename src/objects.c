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

#define _GNU_SOURCE

#include "objects.h"
#include "certificate.h"
#include "tpm.h"
#include "pk11.h"

#include <stdio.h>
#include <stdlib.h> // using malloc(), calloc(), free()
#include <string.h> // using memset()
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

pObject object_get(pObjectList list, int id) {
  while (list != NULL) {
    if (list->object != NULL && list->object->id == id)
      return list->object;
    list = list->next;
  }
  return NULL;
}

void object_add(pObjectList* list, pObject object) {
  pObjectList entry = malloc(sizeof(ObjectList));
  if (!entry) {
    if (object->userdata != NULL)
      free(object->userdata);

    free(object->entries);
    free(object);

    return;
  }

  entry->object = object;
  entry->next = *list;
  *list = entry;
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

pObjectList object_load(TSS2_SYS_CONTEXT *ctx, struct config *config) {
  pObjectList list = NULL;
  
  TPMS_CAPABILITY_DATA persistent;
  TPM2_RC rc = tpm_info(ctx, TPM2_HT_PERSISTENT, &persistent);
  if (rc != TPM2_RC_SUCCESS)
    goto error;

  for (int i = 0; i < persistent.data.handles.count; i++) {
    pUserdataTpm userdata = malloc(sizeof(UserdataTpm));
    if (userdata == NULL)
      goto error;

    memset(userdata, 0, sizeof(UserdataTpm));
    userdata->name.TSS_COMPAT_TMPB(size) = sizeof(TPMU_NAME);
    rc = tpm_readpublic(ctx, persistent.data.handles.handle[i], &userdata->tpm_key, &userdata->name);
    if (rc != TPM2_RC_SUCCESS) {
      free(userdata);
      goto error;
    }
    TPM2B_PUBLIC_KEY_RSA *rsa_key = &userdata->tpm_key.TSS_COMPAT_TMPB(publicArea).unique.rsa;
    TPMS_RSA_PARMS *rsa_key_parms = &userdata->tpm_key.TSS_COMPAT_TMPB(publicArea).parameters.rsaDetail;

    /*
     * fill the label with the same value as the name (they both have
     * different uses ; some application never display the id but only
     * the label). Since the label is an UTF8 string, we need to
     * transform the binary name into a hexadecimal string.
     */
    size_t max_label_size = userdata->name.TSS_COMPAT_TMPB(size);
    if (max_label_size >= sizeof(userdata->label) / 2)
        max_label_size = sizeof(userdata->label) / 2;

    for (size_t n = 0; n < max_label_size; ++n)
      sprintf((char*) userdata->label + 2 * n, "%02X", userdata->name.TSS_COMPAT_TMPB(name[n]));

    userdata->public_object.id = userdata->name.TSS_COMPAT_TMPB(name);
    userdata->public_object.id_size = userdata->name.TSS_COMPAT_TMPB(size);
    userdata->public_object.label = userdata->label;
    userdata->public_object.label_size = max_label_size * 2;
    userdata->public_object.class = CKO_PUBLIC_KEY;
    userdata->public_object.token = CK_TRUE;
    userdata->private_object.id = userdata->name.TSS_COMPAT_TMPB(name);
    userdata->private_object.id_size = userdata->name.TSS_COMPAT_TMPB(size);
    userdata->private_object.label = userdata->label;
    userdata->private_object.label_size = max_label_size * 2;
    userdata->private_object.class = CKO_PRIVATE_KEY;
    userdata->private_object.token = CK_TRUE;
    userdata->key.sign = CK_TRUE;
    userdata->key.decrypt = CK_TRUE;
    userdata->key.key_type = CKK_RSA;
    userdata->modulus.modulus = rsa_key->TSS_COMPAT_TMPB(buffer);
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
    object_add(&list, object);
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
    object_add(&list, object);

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
          object_add(&list, object);
      }
    }
  }

  return list;

error:
  object_free(list);
  return NULL;
}
