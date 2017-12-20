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

#include "object.h"
#include "objects.h"
#include "pk11.h"
#include "utils.h"
#include "tpm.h"

#include <stdio.h>
#include <string.h>

#define MAX_ID_BITS 512

typedef struct userdata_certificate_t {
  char id[MAX_ID_BITS / 4];
  PkcsObject object;
  PkcsX509 certificate;
} UserdataCertificate, *pUserdataCertificate;

static AttrIndex OBJECT_INDEX[] = {
  attr_dynamic_index_of(CKA_ID, PkcsObject, id, id_size),
  attr_index_of(CKA_CLASS, PkcsObject, class)
};

static AttrIndex CERTIFICATE_INDEX[] = {
  attr_dynamic_index_of(CKA_VALUE, PkcsX509, value, value_size),
};

pObject certificate_read(const char* pathname) {
  pObject object = malloc(sizeof(Object));
  if (!object)
    return NULL;

  size_t size = sizeof(UserdataCertificate);
  pUserdataCertificate userdata = (pUserdataCertificate) read_file(pathname, &size);
  if (!userdata) {
    free(object);
    return NULL;
  }

  userdata->object.class = CKO_CERTIFICATE;
  userdata->object.id = userdata->id;
  userdata->object.id_size = 0;
  char* filename = basename(pathname);
  while (userdata->object.id_size < sizeof(userdata->id)) {
    if (sscanf(filename + (userdata->object.id_size * 2), "%2hhx", userdata->id + userdata->object.id_size) != 1)
      break;
    else
      userdata->object.id_size++;
  }

  userdata->certificate.value_size = size;
  userdata->certificate.value = ((char*) userdata) + sizeof(UserdataCertificate);

  object->userdata = userdata;
  object->num_entries = 2;
  object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
  object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->object, OBJECT_INDEX);
  object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->certificate, CERTIFICATE_INDEX);

  return object;
}

pObject certificate_read_from_tpm(TSS2_SYS_CONTEXT *context, TPMI_RH_NV_INDEX index) {
  pObject object = malloc(sizeof(Object));
  if (!object)
    return NULL;

  /* max size of a TPM object in the nvram is TPM2_MAX_NV_BUFFER_SIZE bytes */
  size_t size = TPM2_MAX_NV_BUFFER_SIZE;
  unsigned char *data = malloc(size + sizeof(UserdataCertificate));
  if (!data) {
    free(object);
    return NULL;
  }

  TPM2_RC rc = tpm_nvread(context, index, data + sizeof(UserdataCertificate), &size);
  if (rc != TPM2_RC_SUCCESS) {
    free(object);
    free(data);
    return NULL;
  }

  pUserdataCertificate userdata = (pUserdataCertificate) data;
  userdata->object.class = CKO_CERTIFICATE;
  userdata->object.id = userdata->id;
  userdata->object.id_size = 0;

  userdata->certificate.value_size = size;
  userdata->certificate.value = data + sizeof(UserdataCertificate);

  object->userdata = userdata;
  object->num_entries = 2;
  object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
  object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->object, OBJECT_INDEX);
  object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->certificate, CERTIFICATE_INDEX);

  return object;
}
