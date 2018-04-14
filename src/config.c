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

#include "config.h"
#include "log.h"

#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

int config_load(char* filename, struct config *config) {
  FILE* file = fopen(filename, "r");

  if (file == NULL)
    return -ENOENT;

  char *line = NULL;
  size_t len = 0;

  while (getline(&line, &len, file) != -1) {
    char *key = NULL, *value = NULL;
    if (sscanf(line, "%ms %m[^\n]", &key, &value) == 2) {
      if (strcmp(key, "hostname") == 0) {
        config->hostname = value;
        value = NULL;
      } else if (strcmp(key, "device") == 0) {
        config->device = value;
        value = NULL;
      } else if (strcmp(key, "certificates") == 0) {
        config->certificates = value;
        value = NULL;
      } else if (strcmp(key, "port") == 0)
        config->port = atoi(value);
      else if (strcmp(key, "sign-using-encrypt") == 0)
        config->sign_using_encrypt = strcasecmp(value, "true") == 0;
      else if (strcmp(key, "log-level") == 0)
        config->log_level = atoi(value);
      else if (strcmp(key, "log") == 0) {
        config->log_file = value;
        value = NULL;
      } else if (strcmp(key, "type") == 0) {
        if (strcmp(value, "socket") == 0)
          config->type = TPM_TYPE_SOCKET;
        else if (strcmp(value, "device") == 0)
          config->type = TPM_TYPE_DEVICE;
        else if (strcmp(value, "tabrmd") == 0)
          config->type = TPM_TYPE_TABRMD;
      }
    }
    if (key != NULL)
      free(key);

    if (value != NULL)
      free(value);
  }
  if (line != NULL)
    free(line);

  fclose(file);
  return 0;
}
