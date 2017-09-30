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

#pragma once

#include <stddef.h>

#include <p11-kit/pkcs11.h>

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

void* attr_get(pObject object, CK_ATTRIBUTE_TYPE type, size_t *size);
