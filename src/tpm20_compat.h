/*
 * This file is part of tpm2-pk11.
 * Copyright (C) 2018 Iwan Timmer
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

#include <sapi/tpm20.h>

#ifndef TSS_COMPAT

#define TSS_COMPAT_AUTH_COMMAND_BEGIN
#define TSS_COMPAT_AUTH_RESPONSE_BEGIN

#define TSS_COMPAT_AUTH_COMMAND_VALUE(x) { .count = 1, .auths[0] = { .sessionHandle = x } }
#define TSS_COMPAT_AUTH_RESPONSE_VALUE { .count = 1 }

#define TSS_COMPAT_TMPB(x) x

#else /* TSS_COMPAT */

#define TPM2_RC TPM_RC
#define TPM2_RC_SUCCESS TPM_RC_SUCCESS
#define TPM2_RC_FAILURE TPM_RC_FAILURE

#define TPM2_ST_HASHCHECK TPM_ST_HASHCHECK

#define TPM2_CAP TPM_CAP
#define TPM2_CAP_HANDLES TPM_CAP_HANDLES
#define TPM2_CAP_TPM_PROPERTIES TPM_CAP_TPM_PROPERTIES

#define TPM2_HT_PERSISTENT TPM_HT_PERSISTENT

#define TPM2_PT TPM_PT
#define TPM2_PT_FIXED PT_FIXED
#define TPM2_PT_HR_PERSISTENT TPM_PT_HR_PERSISTENT
#define TPM2_PT_TPM2_HR_PERSISTENT TPM_PT_HR_PERSISTENT
#define TPM2_PT_MANUFACTURER TPM_PT_MANUFACTURER
#define TPM2_PT_REVISION TPM_PT_REVISION
#define TPM2_PT_FIRMWARE_VERSION_1 TPM_PT_FIRMWARE_VERSION_1
#define TPM2_PT_FIRMWARE_VERSION_2 TPM_PT_FIRMWARE_VERSION_2
#define TPM2_PT_ACTIVE_SESSIONS_MAX TPM_PT_ACTIVE_SESSIONS_MAX

#define TPM2_RS_PW TPM_RS_PW

#define TPM2_RH_NULL TPM_RH_NULL

#define TPM2_ALG_NULL TPM_ALG_NULL
#define TPM2_ALG_RSASSA TPM_ALG_RSASSA
#define TPM2_ALG_RSAES TPM_ALG_RSAES
#define TPM2_ALG_SHA1 TPM_ALG_SHA1
#define TPM2_ALG_SHA256 TPM_ALG_SHA256
#define TPM2_ALG_SHA384 TPM_ALG_SHA384
#define TPM2_ALG_SHA512 TPM_ALG_SHA512

#define TPM2_MAX_RSA_KEY_BYTES MAX_RSA_KEY_BYTES
#define TPM2_MAX_TPM_PROPERTIES MAX_TPM_PROPERTIES

#define TPM2_SHA1_DIGEST_SIZE SHA1_DIGEST_SIZE
#define TPM2_SHA256_DIGEST_SIZE SHA256_DIGEST_SIZE
#define TPM2_SHA384_DIGEST_SIZE SHA384_DIGEST_SIZE
#define TPM2_SHA512_DIGEST_SIZE SHA512_DIGEST_SIZE

#define TSS2L_SYS_AUTH_RESPONSE TSS2_SYS_RSP_AUTHS
#define TSS2L_SYS_AUTH_COMMAND TSS2_SYS_CMD_AUTHS

#define TSS_COMPAT_AUTH_COMMAND_BEGIN(x) TPMS_AUTH_COMMAND session_data = { .sessionHandle = x}; \
  TPMS_AUTH_COMMAND *session_data_array[1] = { &session_data };

#define TSS_COMPAT_AUTH_RESPONSE_BEGIN TPMS_AUTH_RESPONSE session_data_out; \
  TPMS_AUTH_RESPONSE *session_data_out_array[1] = { &session_data_out }

#define TSS_COMPAT_AUTH_COMMAND_VALUE(x) { .cmdAuths = &session_data_array[0], .cmdAuthsCount = 1}
#define TSS_COMPAT_AUTH_RESPONSE_VALUE { .rspAuths = &session_data_out_array[0], .rspAuthsCount = 1 }

#define TSS_COMPAT_TMPB(x) t.x

#endif /* TSS_COMPAT */
