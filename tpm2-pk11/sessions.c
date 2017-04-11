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

#include "sessions.h"

#include <stdlib.h>

#include <tcti/tcti_socket.h>

struct session sessions[MAX_SESSIONS] = {0};

static int session_init(struct session* session) {
  TCTI_SOCKET_CONF conf = {
    .hostname = "127.0.0.1",
    .port = 2323,
    .logCallback = NULL,
    .logBufferCallback = NULL,
    .logData = NULL,
  };
  size_t size;
  TSS2_RC rc = InitSocketTcti(NULL, &size, &conf, 0);
  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;
  
  TSS2_TCTI_CONTEXT *tcti_ctx = (TSS2_TCTI_CONTEXT*) malloc(size);
  if (tcti_ctx == NULL)
    goto cleanup;

  rc = InitSocketTcti(tcti_ctx, &size, &conf, 0);
  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;
  
  size = Tss2_Sys_GetContextSize(0);
  session->context = (TSS2_SYS_CONTEXT*) malloc(size);
  if (session->context == NULL)
    goto cleanup;

  TSS2_ABI_VERSION abi_version = {
    .tssCreator = TSSWG_INTEROP,
    .tssFamily = TSS_SAPI_FIRST_FAMILY,
    .tssLevel = TSS_SAPI_FIRST_LEVEL,
    .tssVersion = TSS_SAPI_FIRST_VERSION,
  };
  rc = Tss2_Sys_Initialize(session->context, size, tcti_ctx, &abi_version);

  return 0;

  cleanup:
  if (tcti_ctx != NULL)
    free(tcti_ctx);

  if (session->context != NULL)
    free(session->context);

  return -1;
}

int session_open() {
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (!sessions[i].in_use) {
      sessions[i].in_use = true;
      if (session_init(&sessions[i]) == 0)
        return i;
    }
  }
  return -1;
}
