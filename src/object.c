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

#include "object.h"

void* attr_get(pAttrIndexEntry entries, size_t num_entries, CK_ATTRIBUTE_TYPE type, size_t *size) {
  for (int i = 0; i < num_entries; i++) {
    for (int j = 0; j < entries[i].num_attrs; j++) {
      if (type == entries[i].indexes[j].type) {
        if (entries[i].indexes[j].size_offset == 0) {
          if (size)
            *size = entries[i].indexes[j].size;

          return entries[i].object + entries[i].indexes[j].offset;
        } else {
          if (size)
            *size = *((size_t*) (entries[i].object + entries[i].indexes[j].size_offset));

          return *((void**) (entries[i].object + entries[i].indexes[j].offset));
        }
      }
    }
  }
}
