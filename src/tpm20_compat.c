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

#include "tpm20_compat.h"

/** Guess TSS2_ABI_VERSION numbers
 *
 * ABI version checking method was changed by upstream developers. Here we are
 * trying to guess out the hidden version numbers in the master branch of
 * tpm2-tss. In the future, we may pull those magic version numbers directly
 * from "Tss2_Sys_Initialize.c" of upstream source tree. See:
 * https://github.com/tpm2-software/tpm2-tss/pull/864
 */
const TSS2_ABI_VERSION guess_tss2_abi_version(TSS2_ABI_VERSION *answer) {
#ifndef TSSWG_INTEROP
  const uint32_t TSSWG_INTEROP = 1;
#endif
#ifndef TSS_SAPI_FIRST_FAMILY
  const uint32_t TSS_SAPI_FIRST_FAMILY = 2;
#endif
#ifndef TSS_SAPI_FIRST_LEVEL
  const uint32_t TSS_SAPI_FIRST_LEVEL = 1;
#endif
#ifndef TSS_SAPI_FIRST_VERSION
  const uint32_t TSS_SAPI_FIRST_VERSION = 108;
#endif

  answer->tssCreator = TSSWG_INTEROP;
  answer->tssFamily = TSS_SAPI_FIRST_FAMILY;
  answer->tssLevel = TSS_SAPI_FIRST_LEVEL;
  answer->tssVersion = TSS_SAPI_FIRST_VERSION;

  return (*answer);
}
