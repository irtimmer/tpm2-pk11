/*
 * This file is part of tpm2-pk11.
 * Copyright (C) 2017, 2018 Iwan Timmer
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

#include "tpm20_compat.h"
#include "sessions.h"

#include <stdlib.h>


#define DEFAULT_DEVICE "/dev/tpm0"
#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 2323

unsigned int open_sessions;

int session_init(struct session* session, struct config *config) {
  session->context = NULL;

  size_t size = 0;
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
  TSS2_RC rc;

#ifdef TCTI_DEVICE_ENABLED
  TSS_COMPAT_TCTI_DEVICE_CONF device_conf;
#endif // TCTI_DEVICE_ENABLED
  
  switch(config->type) {
#ifdef TCTI_SOCKET_ENABLED
    case TPM_TYPE_SOCKET:
      rc = InitSocketTcti(NULL, &size, NULL, 0);
      break;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_MSSIM_ENABLED
    case TPM_TYPE_SOCKET:
      rc = Tss2_Tcti_Mssim_Init(NULL, &size, NULL);
      break;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_DEVICE_ENABLED
    case TPM_TYPE_DEVICE:
      rc = Tss2_Tcti_Device_Init(NULL, &size, device_conf);
      break;
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
    case TPM_TYPE_TABRMD:
      rc = Tss2_Tcti_Tabrmd_Init(NULL, &size, NULL);
      break;
#endif // TCTI_TABRMD_ENABLED
    default:
      rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
      break;
  }

  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;

  tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
  if (tcti_ctx == NULL)
    goto cleanup;

#ifdef TCTI_SOCKET_ENABLED
  TCTI_SOCKET_CONF socket_conf;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_MSSIM_ENABLED
  const char tcti_uri[256];
#endif // TCTI_MSSIM_ENABLED

  switch(config->type) {
#ifdef TCTI_SOCKET_ENABLED
    case TPM_TYPE_SOCKET:
      socket_conf = (TCTI_SOCKET_CONF) { .hostname = config->hostname != NULL ? config->hostname : DEFAULT_HOSTNAME, .port = config->port > 0 ? config->port : DEFAULT_PORT };
      rc = InitSocketTcti(tcti_ctx, &size, &socket_conf, 0);
      break;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_MSSIM_ENABLED
    case TPM_TYPE_SOCKET:
      snprintf("tcp://%s:%d", sizeof(tcti_uri), config->hostname != NULL ? config->hostname : DEFAULT_HOSTNAME, config->port > 0 ? config->port : DEFAULT_PORT);
      rc = Tss2_Tcti_Mssim_Init(tcti_ctx, &size, (const char*) &tcti_uri);
      break;
#endif // TCTI_MSSIM_ENABLED
#ifdef TCTI_DEVICE_ENABLED
    case TPM_TYPE_DEVICE: {
      TSS_COMPAT_DEVICE_CONF(device_conf, config->device != NULL ? config->device : DEFAULT_DEVICE);
      rc = Tss2_Tcti_Device_Init(tcti_ctx, &size, device_conf);
      break;
    }
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
    case TPM_TYPE_TABRMD:
      rc = Tss2_Tcti_Tabrmd_Init(tcti_ctx, &size, NULL);
      break;
#endif // TCTI_TABRMD_ENABLED
    default:
      rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
      break;
  }

  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;
  
  size = Tss2_Sys_GetContextSize(0);
  session->context = (TSS2_SYS_CONTEXT*) calloc(1, size);
  if (session->context == NULL)
    goto cleanup;

  TSS2_ABI_VERSION abi_version;
  guess_tss2_abi_version(&abi_version);
  rc = Tss2_Sys_Initialize(session->context, size, tcti_ctx, &abi_version);

  session->objects = object_load(session->context, config);
  open_sessions++;

  return 0;

  cleanup:
  if (tcti_ctx != NULL)
    free(tcti_ctx);

  if (session->context != NULL)
    free(session->context);

  return -1;
}

void session_close(struct session* session) {
  object_free(session->objects);
  Tss2_Sys_Finalize(session->context);
  open_sessions--;
}
