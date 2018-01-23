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

#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

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
    va_list args;
    va_start(args, format);
    fprintf(log_stream, "[tpm-pk11] ");
    vfprintf(log_stream, format, args);
    fprintf(log_stream, "\n");
    va_end(args);
  }
}
