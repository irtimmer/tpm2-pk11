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

#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

void* map_file(char* filename, size_t* length) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    *length = 0;
    return NULL;
  }

  struct stat s;
  void *mapped = NULL;
  int ret = fstat(fd, &s);
  if (ret < 0) {
    *length = 0;
    goto cleanup;
  }

  *length = s.st_size;
  mapped = mmap(0, *length, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mapped == MAP_FAILED) {
    *length = 0;
    goto cleanup;
  }

  cleanup:
  close(fd);
  return mapped;
}
