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
