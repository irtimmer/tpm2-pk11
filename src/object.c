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

#include "object.h"

AttrIndex OBJECT_INDEX[] = {
  attr_dynamic_index_of(CKA_ID, PkcsObject, id, id_size),
  attr_dynamic_index_of(CKA_LABEL, PkcsObject, label, label_size),
  attr_index_of(CKA_CLASS, PkcsObject, class),
  attr_index_of(CKA_TOKEN, PkcsObject, token)
};

AttrIndex KEY_INDEX[] = {
  attr_index_of(CKA_SIGN, PkcsKey, sign),
  attr_index_of(CKA_DECRYPT, PkcsKey, decrypt),
  attr_index_of(CKA_KEY_TYPE, PkcsKey, key_type)
};

AttrIndex PUBLIC_KEY_INDEX[] = {
  attr_index_of(CKA_PUBLIC_EXPONENT, PkcsPublicKey, exponent)
};

AttrIndex MODULUS_INDEX[] = {
  attr_dynamic_index_of(CKA_MODULUS, PkcsModulus, modulus, modulus_size),
  attr_index_of(CKA_MODULUS_BITS, PkcsModulus, bits),
};

AttrIndex CERTIFICATE_INDEX[] = {
  attr_dynamic_index_of(CKA_VALUE, PkcsX509, value, value_size),
  attr_dynamic_index_of(CKA_SUBJECT, PkcsX509, subject, subject_size),
  attr_dynamic_index_of(CKA_ISSUER, PkcsX509, issuer, issuer_size),
  attr_dynamic_index_of(CKA_SERIAL_NUMBER, PkcsX509, serial, serial_size),
  attr_index_of(CKA_CERTIFICATE_TYPE, PkcsX509, cert_type),
};

void* attr_get(pObject object, CK_ATTRIBUTE_TYPE type, size_t *size) {
  for (int i = 0; i < object->num_entries; i++) {
    pAttrIndexEntry entries = &object->entries[i];
    for (int j = 0; j < entries->num_attrs; j++) {
      if (type == entries->indexes[j].type) {
        pAttrIndex index = &entries->indexes[j];
        if (index->size_offset == 0) {
          if (size)
            *size = index->size;

          return entries->object + index->offset;
        } else {
          if (size)
            *size = *((size_t*) (entries->object + index->size_offset));

          return *((void**) (entries->object + index->offset));
        }
      }
    }
  }

  return NULL;
}
