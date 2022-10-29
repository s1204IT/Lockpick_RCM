/*
 * Copyright (c) 2019-2021 shchmue
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

#include <utils/types.h>

#include "../hos/hos.h"

#define AES_128_KEY_SIZE 16
#define RSA_2048_KEY_SIZE 256

#define RSA_PUBLIC_EXPONENT 65537

// Lockpick_RCM keyslots
#define KS_BIS_00_0 0
#define KS_BIS_00_1 1
#define KS_BIS_01_0 2
#define KS_BIS_01_1 3
#define KS_BIS_02_0 4
#define KS_BIS_02_1 5
#define KS_AES_CTR  6
#define KS_AES_ECB  8
#define KS_AES_CMAC 10

// Mariko keyslots
#define KS_MARIKO_KEK 12
#define KS_MARIKO_BEK 13

// Other Switch keyslots
#define KS_TSEC        12
#define KS_SECURE_BOOT 14

// Atmosphere keygen keyslots
#define KS_TSEC_ROOT_DEV 11
#define KS_TSEC_ROOT     13

// only tickets of type Rsa2048Sha256 are expected
typedef struct {
    u32 signature_type;   // always 0x10004
    u8 signature[RSA_2048_KEY_SIZE];
    u8 sig_padding[0x3C];
    char issuer[0x40];
    u8 titlekey_block[RSA_2048_KEY_SIZE];
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
    u8 private_exponent[RSA_2048_KEY_SIZE];
    u8 modulus[RSA_2048_KEY_SIZE];
    u8 public_exponent[4];
    u8 reserved[0xC];
} rsa_keypair_t;

typedef struct {
    u8 master_kek[AES_128_KEY_SIZE];
    u8 data[0x70];
    u8 package1_key[AES_128_KEY_SIZE];
} keyblob_t;

typedef struct {
    u8 cmac[0x10];
    u8 iv[0x10];
    keyblob_t key_data;
    u8 unused[0x150];
} encrypted_keyblob_t;

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

typedef enum {
    SEAL_KEY_LOAD_AES_KEY = 0,
    SEAL_KEY_DECRYPT_DEVICE_UNIQUE_DATA = 1,
    SEAL_KEY_IMPORT_LOTUS_KEY = 2,
    SEAL_KEY_IMPORT_ES_DEVICE_KEY = 3,
    SEAL_KEY_REENCRYPT_DEVICE_UNIQUE_DATA = 4,
    SEAL_KEY_IMPORT_SSL_KEY = 5,
    SEAL_KEY_IMPORT_ES_CLIENT_CERT_KEY = 6,
} seal_key_t;

typedef enum {
    NOT_DEVICE_UNIQUE = 0,
    IS_DEVICE_UNIQUE = 1,
} device_unique_t;

#define SET_SEAL_KEY_INDEX(x) (((x) & 7) << 5)
#define GET_SEAL_KEY_INDEX(x) (((x) >> 5) & 7)
#define GET_IS_DEVICE_UNIQUE(x) ((x) & 1)

#define SSL_RSA_KEY_SIZE (RSA_2048_KEY_SIZE + AES_128_KEY_SIZE)

typedef struct {
    u8  temp_key[AES_128_KEY_SIZE],
        bis_key[4][AES_128_KEY_SIZE * 2],
        device_key[AES_128_KEY_SIZE],
        device_key_4x[AES_128_KEY_SIZE],
        sd_seed[AES_128_KEY_SIZE],
        // FS-related keys
        header_key[AES_128_KEY_SIZE * 2],
        save_mac_key[AES_128_KEY_SIZE],
        // other sysmodule keys
        eticket_rsa_kek[AES_128_KEY_SIZE],
        eticket_rsa_kek_personalized[AES_128_KEY_SIZE],
        ssl_rsa_kek[AES_128_KEY_SIZE],
        ssl_rsa_kek_legacy[AES_128_KEY_SIZE],
        ssl_rsa_kek_personalized[AES_128_KEY_SIZE],
        ssl_rsa_key[RSA_2048_KEY_SIZE + 0x20],
        // keyblob-derived families
        keyblob_key[KB_FIRMWARE_VERSION_600 + 1][AES_128_KEY_SIZE],
        keyblob_mac_key[KB_FIRMWARE_VERSION_600 + 1][AES_128_KEY_SIZE],
        package1_key[KB_FIRMWARE_VERSION_600 + 1][AES_128_KEY_SIZE],
        // master key-derived families
        key_area_key[3][KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        master_kek[KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        master_key[KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        package2_key[KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        titlekek[KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        tsec_key[AES_128_KEY_SIZE],
        tsec_root_key[AES_128_KEY_SIZE];
    u32 sbk[4];
    keyblob_t keyblob[KB_FIRMWARE_VERSION_600 + 1];
    rsa_keypair_t eticket_rsa_keypair;
} key_derivation_ctx_t;

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
