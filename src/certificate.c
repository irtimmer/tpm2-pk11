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

#include "object.h"
#include "objects.h"
#include "pk11.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h> // using malloc(), calloc(), free(), getenv()
#include <string.h>

#include <libtasn1.h>

#define MAX_ID_BITS 512
#define MAX_DER_LENGTH 256

extern const asn1_static_node pkix_asn1_tab[];

typedef struct userdata_certificate_t {
  CK_BYTE id[MAX_ID_BITS / 4];
  CK_UTF8CHAR label[MAX_ID_BITS / 2];
  CK_BYTE subject[MAX_DER_LENGTH];
  CK_BYTE issuer[MAX_DER_LENGTH];
  CK_BYTE serial[MAX_DER_LENGTH];
  PkcsObject object;
  PkcsX509 certificate;
} UserdataCertificate, *pUserdataCertificate;



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
  userdata->object.token = CK_TRUE;
  userdata->object.id = userdata->id;
  userdata->object.id_size = 0;
  userdata->object.label = userdata->label;
  char* filename = basename(pathname);
  while (userdata->object.id_size < sizeof(userdata->id)) {
    if (sscanf(filename + (userdata->object.id_size * 2), "%2hhx", userdata->id + userdata->object.id_size) != 1)
      break;

    sprintf((char*) userdata->label + userdata->object.id_size * 2, "%02X", userdata->id[userdata->object.id_size]);
    userdata->object.id_size++;
  }

  userdata->object.label_size = userdata->object.id_size * 2;

  userdata->certificate.value_size = size;
  userdata->certificate.value = ((char*) userdata) + sizeof(UserdataCertificate);
  userdata->certificate.cert_type = CKC_X_509;
  userdata->certificate.subject = userdata->subject;
  userdata->certificate.subject_size = 0;
  userdata->certificate.issuer = userdata->issuer;
  userdata->certificate.issuer_size = 0;
  userdata->certificate.serial = userdata->serial;
  userdata->certificate.serial_size = 0;

  ASN1_TYPE definition = ASN1_TYPE_EMPTY;
  ASN1_TYPE element = ASN1_TYPE_EMPTY;
  char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

  asn1_array2tree(pkix_asn1_tab, &definition, errorDescription);
  asn1_create_element(definition, "PKIX1.Certificate", &element);
  if (asn1_der_decoding(&element, userdata->certificate.value, userdata->certificate.value_size, errorDescription) != ASN1_SUCCESS) {
    free(object);
    free(userdata);
    return NULL;
  }

  int length = MAX_DER_LENGTH;
  if (asn1_der_coding(element, "tbsCertificate.subject", userdata->subject, &length, errorDescription) == ASN1_SUCCESS)
    userdata->certificate.subject_size = length;

  length = MAX_DER_LENGTH;
  if (asn1_der_coding(element, "tbsCertificate.issuer", userdata->issuer, &length, errorDescription) == ASN1_SUCCESS)
    userdata->certificate.issuer_size = length;

  length = MAX_DER_LENGTH;
  if (asn1_der_coding(element, "tbsCertificate.serialNumber", userdata->serial, &length, errorDescription) == ASN1_SUCCESS)
    userdata->certificate.serial_size = length;

  asn1_delete_structure(&definition);
  asn1_delete_structure(&element);

  object->userdata = userdata;
  object->num_entries = 2;
  object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
  object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->object, OBJECT_INDEX);
  object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->certificate, CERTIFICATE_INDEX);

  return object;
}
