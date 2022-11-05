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

#ifndef _ES_CRYPTO_H_
#define _ES_CRYPTO_H_

#include "crypto.h"
#include "es_types.h"

#include <utils/types.h>

static const u8 eticket_rsa_kek_source[0x10] __attribute__((aligned(4))) = {
    0XDB, 0XA4, 0X51, 0X12, 0X4C, 0XA0, 0XA9, 0X83, 0X68, 0X14, 0XF5, 0XED, 0X95, 0XE3, 0X12, 0X5B};
static const u8 eticket_rsa_kek_source_dev[0x10] __attribute__((aligned(4))) = {
    0xBE, 0xC0, 0xBC, 0x8E, 0x75, 0xA0, 0xF6, 0x0C, 0x4A, 0x56, 0x64, 0x02, 0x3E, 0xD4, 0x9C, 0xD5};
static const u8 eticket_rsa_kek_source_legacy[0x10] __attribute__((aligned(4))) = {
    0x88, 0x87, 0x50, 0x90, 0xA6, 0x2F, 0x75, 0x70, 0xA2, 0xD7, 0x71, 0x51, 0xAE, 0x6D, 0x39, 0x87};
static const u8 eticket_rsa_kekek_source[0x10] __attribute__((aligned(4))) = {
    0X46, 0X6E, 0X57, 0XB7, 0X4A, 0X44, 0X7F, 0X02, 0XF3, 0X21, 0XCD, 0XE5, 0X8F, 0X2F, 0X55, 0X35};

bool test_eticket_rsa_keypair(const eticket_rsa_keypair_t *keypair);

void es_derive_rsa_kek_device_unique(key_storage_t *keys, void *out_rsa_kek, u32 generation, bool is_dev);
void es_derive_rsa_kek_legacy(key_storage_t *keys, void *out_rsa_kek);
void es_derive_rsa_kek_original(key_storage_t *keys, void *out_rsa_kek, bool is_dev);

#endif
