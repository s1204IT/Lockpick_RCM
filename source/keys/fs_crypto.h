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

#ifndef _FS_CRYPTO_H_
#define _FS_CRYPTO_H_

#include "crypto.h"

#include <utils/types.h>

static const u8 bis_kek_source[0x10] __attribute__((aligned(4))) = {
    0x34, 0xC1, 0xA0, 0xC4, 0x82, 0x58, 0xF8, 0xB4, 0xFA, 0x9E, 0x5E, 0x6A, 0xDA, 0xFC, 0x7E, 0x4F};
static const u8 bis_key_sources[3][0x20] __attribute__((aligned(4))) = {
    {0xF8, 0x3F, 0x38, 0x6E, 0x2C, 0xD2, 0xCA, 0x32, 0xA8, 0x9A, 0xB9, 0xAA, 0x29, 0xBF, 0xC7, 0x48,
     0x7D, 0x92, 0xB0, 0x3A, 0xA8, 0xBF, 0xDE, 0xE1, 0xA7, 0x4C, 0x3B, 0x6E, 0x35, 0xCB, 0x71, 0x06},
    {0x41, 0x00, 0x30, 0x49, 0xDD, 0xCC, 0xC0, 0x65, 0x64, 0x7A, 0x7E, 0xB4, 0x1E, 0xED, 0x9C, 0x5F,
     0x44, 0x42, 0x4E, 0xDA, 0xB4, 0x9D, 0xFC, 0xD9, 0x87, 0x77, 0x24, 0x9A, 0xDC, 0x9F, 0x7C, 0xA4},
    {0x52, 0xC2, 0xE9, 0xEB, 0x09, 0xE3, 0xEE, 0x29, 0x32, 0xA1, 0x0C, 0x1F, 0xB6, 0xA0, 0x92, 0x6C,
     0x4D, 0x12, 0xE1, 0x4B, 0x2A, 0x47, 0x4C, 0x1C, 0x09, 0xCB, 0x03, 0x59, 0xF0, 0x15, 0xF4, 0xE4}
};

static const u8 header_kek_source[0x10] __attribute__((aligned(4))) = {
    0x1F, 0x12, 0x91, 0x3A, 0x4A, 0xCB, 0xF0, 0x0D, 0x4C, 0xDE, 0x3A, 0xF6, 0xD5, 0x23, 0x88, 0x2A};
static const u8 header_key_source[0x20] __attribute__((aligned(4))) = {
    0x5A, 0x3E, 0xD8, 0x4F, 0xDE, 0xC0, 0xD8, 0x26, 0x31, 0xF7, 0xE2, 0x5D, 0x19, 0x7B, 0xF5, 0xD0,
    0x1C, 0x9B, 0x7B, 0xFA, 0xF6, 0x28, 0x18, 0x3D, 0x71, 0xF6, 0x4D, 0x73, 0xF1, 0x50, 0xB9, 0xD2};

static const u8 key_area_key_sources[3][0x10] __attribute__((aligned(4))) = {
    {0x7F, 0x59, 0x97, 0x1E, 0x62, 0x9F, 0x36, 0xA1, 0x30, 0x98, 0x06, 0x6F, 0x21, 0x44, 0xC3, 0x0D}, // application
    {0x32, 0x7D, 0x36, 0x08, 0x5A, 0xD1, 0x75, 0x8D, 0xAB, 0x4E, 0x6F, 0xBA, 0xA5, 0x55, 0xD8, 0x82}, // ocean
    {0x87, 0x45, 0xF1, 0xBB, 0xA6, 0xBE, 0x79, 0x64, 0x7D, 0x04, 0x8B, 0xA6, 0x7B, 0x5F, 0xDA, 0x4A}, // system
};

static const u8 save_mac_kek_source[0x10] __attribute__((aligned(4))) = {
    0XD8, 0X9C, 0X23, 0X6E, 0XC9, 0X12, 0X4E, 0X43, 0XC8, 0X2B, 0X03, 0X87, 0X43, 0XF9, 0XCF, 0X1B};
static const u8 save_mac_key_source[0x10] __attribute__((aligned(4))) = {
    0XE4, 0XCD, 0X3D, 0X4A, 0XD5, 0X0F, 0X74, 0X28, 0X45, 0XA4, 0X87, 0XE5, 0XA0, 0X63, 0XEA, 0X1F};

static const u8 save_mac_sd_card_kek_source[0x10] __attribute__((aligned(4))) = {
    0X04, 0X89, 0XEF, 0X5D, 0X32, 0X6E, 0X1A, 0X59, 0XC4, 0XB7, 0XAB, 0X8C, 0X36, 0X7A, 0XAB, 0X17};
static const u8 save_mac_sd_card_key_source[0x10] __attribute__((aligned(4))) = {
    0X6F, 0X64, 0X59, 0X47, 0XC5, 0X61, 0X46, 0XF9, 0XFF, 0XA0, 0X45, 0XD5, 0X95, 0X33, 0X29, 0X18};

static const u8 sd_card_custom_storage_key_source[0x20] __attribute__((aligned(4))) = {
    0X37, 0X0C, 0X34, 0X5E, 0X12, 0XE4, 0XCE, 0XFE, 0X21, 0XB5, 0X8E, 0X64, 0XDB, 0X52, 0XAF, 0X35,
    0X4F, 0X2C, 0XA5, 0XA3, 0XFC, 0X99, 0X9A, 0X47, 0XC0, 0X3E, 0XE0, 0X04, 0X48, 0X5B, 0X2F, 0XD0};
static const u8 sd_card_kek_source[0x10] __attribute__((aligned(4))) = {
    0X88, 0X35, 0X8D, 0X9C, 0X62, 0X9B, 0XA1, 0XA0, 0X01, 0X47, 0XDB, 0XE0, 0X62, 0X1B, 0X54, 0X32};
static const u8 sd_card_nca_key_source[0x20] __attribute__((aligned(4))) = {
    0X58, 0X41, 0XA2, 0X84, 0X93, 0X5B, 0X56, 0X27, 0X8B, 0X8E, 0X1F, 0XC5, 0X18, 0XE9, 0X9F, 0X2B,
    0X67, 0XC7, 0X93, 0XF0, 0XF2, 0X4F, 0XDE, 0XD0, 0X75, 0X49, 0X5D, 0XCA, 0X00, 0X6D, 0X99, 0XC2};
static const u8 sd_card_save_key_source[0x20] __attribute__((aligned(4))) = {
    0X24, 0X49, 0XB7, 0X22, 0X72, 0X67, 0X03, 0XA8, 0X19, 0X65, 0XE6, 0XE3, 0XEA, 0X58, 0X2F, 0XDD,
    0X9A, 0X95, 0X15, 0X17, 0XB1, 0X6E, 0X8F, 0X7F, 0X1F, 0X68, 0X26, 0X31, 0X52, 0XEA, 0X29, 0X6A};

void fs_derive_bis_keys(key_storage_t *keys, u8 out_bis_keys[4][32], u32 generation);
void fs_derive_header_key(key_storage_t *keys, void *out_key);
void fs_derive_key_area_key(key_storage_t *keys, void *out_key, u32 source_type, u32 generation);
void fs_derive_save_mac_key(key_storage_t *keys, void *out_key);

#endif
