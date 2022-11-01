/*
 * Copyright (c) 2019-2022 shchmue
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

#ifndef _KEYS_H_
#define _KEYS_H_

#include "crypto.h"

#include "../hos/hos.h"
#include <sec/se_t210.h>
#include <utils/types.h>

// only tickets of type Rsa2048Sha256 are expected
typedef struct {
    u32 signature_type;   // always 0x10004
    u8 signature[SE_RSA2048_DIGEST_SIZE];
    u8 sig_padding[0x3C];
    char issuer[0x40];
    u8 titlekey_block[SE_RSA2048_DIGEST_SIZE];
    u8 format_version;
    u8 titlekey_type;
    u16 ticket_version;
    u8 license_type;
    u8 common_key_id;
    u16 property_mask;
    u64 reserved;
    u64 ticket_id;
    u64 device_id;
    u8 rights_id[0x10];
    u32 account_id;
    u32 sect_total_size;
    u32 sect_hdr_offset;
    u16 sect_hdr_count;
    u16 sect_hdr_entry_size;
    u8 padding[0x140];
} ticket_t;

typedef struct {
    u8 rights_id[0x10];
    u64 ticket_id;
    u32 account_id;
    u16 property_mask;
    u16 reserved;
} ticket_record_t;

typedef struct {
    u8 read_buffer[SZ_256K];
    u8 rights_ids[SZ_256K / 0x10][0x10];
    u8 titlekeys[SZ_256K / 0x10][0x10];
} titlekey_buffer_t;

typedef struct {
    char phrase[0xE];
    u8 seed[0xE];
    u8 hmac_key[0x10];
    char phrase_for_verif[0xE];
    u8 seed_for_verif[0x10];
    u8 hmac_key_for_verif[0x10];
    u8 ctr_key[0x10];
    u8 ctr_iv[0x10];
    u8 pad[6];
} nfc_keyblob_t;

typedef struct {
    u8 hmac_key[0x10];
    char phrase[0xE];
    u8 rsvd;
    u8 seed_size;
    u8 seed[0x10];
    u8 xor_pad[0x20];
} nfc_save_key_t;

typedef struct {
    char rights_id[0x20];
    char equals[3];
    char titlekey[0x20];
    char newline[1];
} titlekey_text_buffer_t;

#define TPRINTF(text) \
    end_time = get_tmr_us(); \
    gfx_printf(text" done in %d us\n", end_time - start_time); \
    start_time = get_tmr_us(); \
    minerva_periodic_training()

#define TPRINTFARGS(text, args...) \
    end_time = get_tmr_us(); \
    gfx_printf(text" done in %d us\n", args, end_time - start_time); \
    start_time = get_tmr_us(); \
    minerva_periodic_training()

// save key wrapper
#define SAVE_KEY(name) _save_key(#name, name, sizeof(name), text_buffer)
// save key with different name than variable
#define SAVE_KEY_VAR(name, varname) _save_key(#name, varname, sizeof(varname), text_buffer)
// save key family wrapper
#define SAVE_KEY_FAMILY(name, start) _save_key_family(#name, name, start, ARRAY_SIZE(name), sizeof(*(name)), text_buffer)
// save key family with different name than variable
#define SAVE_KEY_FAMILY_VAR(name, varname, start) _save_key_family(#name, varname, start, ARRAY_SIZE(varname), sizeof(*(varname)), text_buffer)

void dump_keys();
int save_mariko_partial_keys(u32 start, u32 count, bool append);
void derive_amiibo_keys();

#endif
