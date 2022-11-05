/*
 * Copyright (c) 2022 shchmue
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ES_TYPES_H_
#define _ES_TYPES_H_

#include <sec/se_t210.h>
#include <utils/types.h>

typedef struct {
    u8 private_exponent[SE_RSA2048_DIGEST_SIZE];
    u8 modulus[SE_RSA2048_DIGEST_SIZE];
    u32 public_exponent;
    u8 reserved[0xC];
} eticket_rsa_keypair_t;

#endif
