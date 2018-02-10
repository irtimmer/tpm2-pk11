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
#include <string.h>
#include <stdlib.h>

void strncpy_pad(char *dest, size_t dest_len, const char *src, size_t n) {
  size_t src_len = strlen(src);
  if (src_len > n)
    src_len = n;

  memcpy(dest, src, src_len < dest_len ? src_len : dest_len);
  if (src_len < dest_len)
    memset(dest + src_len, ' ', dest_len - src_len);
}

void retmem(void* dest, size_t* size, const void* src, size_t n) {
  if (dest && n <= *size)
    memcpy(dest, src, n);

  *size = n;
}

void* read_file(const char* filename, size_t* length) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    *length = 0;
    return NULL;
  }

  struct stat s;
  char* buffer = NULL;
  int ret = fstat(fd, &s);
  if (ret < 0) {
    *length = 0;
    goto cleanup;
  }

  size_t pre_length = *length;
  *length = s.st_size;
  buffer = malloc(*length + pre_length);
  if (buffer == NULL || read(fd, buffer + pre_length, *length) != *length)
    *length = 0;

  cleanup:
  close(fd);
  return buffer;
}
