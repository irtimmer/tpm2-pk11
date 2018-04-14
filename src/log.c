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

#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static int log_level = NONE;
static FILE* log_stream = NULL;

void log_init(char* filename, int level) {
  log_level = level;
  if (filename != NULL) {
    if (strcmp(filename, "stdout") == 0)
      log_stream = stdout;
    else if (strcmp(filename, "stderr") == 0)
      log_stream = stderr;
    else
      log_stream = fopen(filename, "a");
  }
}

void print_log(int level, const char* format, ...) {
  if (log_stream != NULL && level <= log_level) {
    char buffer[20];
    time_t now = time(0);
    struct tm* time_now = localtime(&now);

    va_list args;
    va_start(args, format);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_now);
    fprintf(log_stream, "%s [tpm-pk11] ", buffer);
    vfprintf(log_stream, format, args);
    fprintf(log_stream, "\n");
    va_end(args);
  }
}
