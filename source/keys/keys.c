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

#include "keys.h"

#include "../../keygen/tsec_keygen.h"

#include "../config.h"
#include <display/di.h>
#include "../frontend/gui.h"
#include <gfx_utils.h>
#include "../gfx/tui.h"
#include "../hos/hos.h"
#include <libs/fatfs/ff.h>
#include <libs/nx_savedata/save.h>
#include <mem/heap.h>
#include <mem/minerva.h>
#include <mem/sdram.h>
#include <sec/se.h>
#include <sec/se_t210.h>
#include <sec/tsec.h>
#include <soc/fuse.h>
#include <mem/smmu.h>
#include <soc/t210.h>
#include "../storage/emummc.h"
#include "../storage/nx_emmc.h"
#include "../storage/nx_emmc_bis.h"
#include <storage/nx_sd.h>
#include <storage/sdmmc.h>
#include <utils/btn.h>
#include <utils/list.h>
#include <utils/sprintf.h>
#include <utils/util.h>

#include "key_sources.inl"

#include <string.h>

extern hekate_config h_cfg;

static u32 _key_count = 0, _titlekey_count = 0;
static u32 start_time, end_time;
u32 color_idx = 0;

static ALWAYS_INLINE u32 _read_le_u32(const void *buffer, u32 offset) {
    return (*(u8*)(buffer + offset + 0)        ) |
           (*(u8*)(buffer + offset + 1) << 0x08) |
           (*(u8*)(buffer + offset + 2) << 0x10) |
           (*(u8*)(buffer + offset + 3) << 0x18);
}

static ALWAYS_INLINE u32 _read_be_u32(const void *buffer, u32 offset) {
    return (*(u8*)(buffer + offset + 3)        ) |
           (*(u8*)(buffer + offset + 2) << 0x08) |
           (*(u8*)(buffer + offset + 1) << 0x10) |
           (*(u8*)(buffer + offset + 0) << 0x18);
}

// key functions
static int  _key_exists(const void *data) { return memcmp(data, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0; };
static void _save_key(const char *name, const void *data, u32 len, char *outbuf);
static void _save_key_family(const char *name, const void *data, u32 start_key, u32 num_keys, u32 len, char *outbuf);
static void _generate_aes_kek(u32 ks, key_derivation_ctx_t *keys, void *out_kek, const void *kek_source, u32 generation, u32 option);
static void _generate_aes_key(u32 ks, key_derivation_ctx_t *keys, void *out_key, u32 key_size, const void *access_key, const void *key_source);
static void _load_aes_key(u32 ks, void *out_key, const void *access_key, const void *key_source);
static void _get_device_unique_data_key(u32 ks, void *out_key, const void *access_key, const void *key_source);
static void _decrypt_aes_key(u32 ks, key_derivation_ctx_t *keys, void *out_key, const void *key_source, u32 generation, u32 option);
static void _generate_specific_aes_key(u32 ks, key_derivation_ctx_t *keys, void *out_key, const void *key_source, u32 generation);
static void _get_device_key(u32 ks, key_derivation_ctx_t *keys, void *out_device_key, u32 generation);
static void _ghash(u32 ks, void *dst, const void *src, u32 src_size, const void *j_block, bool encrypt);
// titlekey functions
static bool _test_key_pair(const void *E, const void *D, const void *N);

static void _derive_master_key_mariko(key_derivation_ctx_t *keys, bool is_dev) {
    // Relies on the SBK being properly set in slot 14
    se_aes_crypt_block_ecb(14, DECRYPT, keys->device_key_4x, device_master_key_source_kek_source);
    // Derive all master keys based on Mariko KEK
    for (u32 i = KB_FIRMWARE_VERSION_600; i < ARRAY_SIZE(mariko_master_kek_sources) + KB_FIRMWARE_VERSION_600; i++) {
        // Relies on the Mariko KEK being properly set in slot 12
        se_aes_crypt_block_ecb(12, DECRYPT, keys->master_kek[i], is_dev ? &mariko_master_kek_sources_dev[i - KB_FIRMWARE_VERSION_600] : &mariko_master_kek_sources[i - KB_FIRMWARE_VERSION_600]); // mkek = unwrap(mariko_kek, mariko_kek_source)
        _load_aes_key(8, keys->master_key[i], keys->master_kek[i], master_key_source);
    }
}

static int _run_ams_keygen(key_derivation_ctx_t *keys) {
    tsec_ctxt_t tsec_ctxt;
    tsec_ctxt.fw = tsec_keygen;
    tsec_ctxt.size = sizeof(tsec_keygen);
    tsec_ctxt.type = TSEC_FW_TYPE_NEW;

    u32 retries = 0;
    while (tsec_query(keys->temp_key, &tsec_ctxt) < 0) {
        retries++;
        if (retries > 15) {
            EPRINTF("Failed to run keygen.");
            return -1;
        }
    }

    return 0;
}

static void _derive_master_keys_from_latest_key(key_derivation_ctx_t *keys, bool is_dev) {
    if (!h_cfg.t210b01) {
        u32 tsec_root_key_slot = is_dev ? 11 : 13;
        // Derive all master keys based on current root key
        for (u32 i = KB_FIRMWARE_VERSION_810 - KB_FIRMWARE_VERSION_620; i < ARRAY_SIZE(master_kek_sources); i++) {
            se_aes_crypt_block_ecb(tsec_root_key_slot, DECRYPT, keys->master_kek[i + KB_FIRMWARE_VERSION_620], master_kek_sources[i]); // mkek = unwrap(tsec_root, mkeks)
            _load_aes_key(8, keys->master_key[i + KB_FIRMWARE_VERSION_620], keys->master_kek[i + KB_FIRMWARE_VERSION_620], master_key_source);
        }
    }

    // Derive all lower master keys
    for (u32 i = KB_FIRMWARE_VERSION_MAX; i > 0; i--) {
        _load_aes_key(8, keys->master_key[i - 1], keys->master_key[i], is_dev ? master_key_vectors_dev[i] : master_key_vectors[i]);
    }
    _load_aes_key(8, keys->temp_key, keys->master_key[0], is_dev ? master_key_vectors_dev[0] : master_key_vectors[0]);

    if (_key_exists(keys->temp_key)) {
        EPRINTFARGS("Unable to derive master keys for %s.", is_dev ? "dev" : "prod");
        memset(keys->master_key, 0, sizeof(keys->master_key));
    }
}

static void _derive_keyblob_keys(key_derivation_ctx_t *keys) {
    u8 *keyblob_block = (u8 *)calloc(KB_FIRMWARE_VERSION_600 + 1, NX_EMMC_BLOCKSIZE);
    u32 keyblob_mac[AES_128_KEY_SIZE / 4] = {0};
    bool have_keyblobs = true;

    if (FUSE(FUSE_PRIVATE_KEY0) == 0xFFFFFFFF) {
        u8 *aes_keys = (u8 *)calloc(SZ_4K, 1);
        se_get_aes_keys(aes_keys + SZ_2K, aes_keys, AES_128_KEY_SIZE);
        memcpy(keys->sbk, aes_keys + 14 * AES_128_KEY_SIZE, AES_128_KEY_SIZE);
        free(aes_keys);
    } else {
        keys->sbk[0] = FUSE(FUSE_PRIVATE_KEY0);
        keys->sbk[1] = FUSE(FUSE_PRIVATE_KEY1);
        keys->sbk[2] = FUSE(FUSE_PRIVATE_KEY2);
        keys->sbk[3] = FUSE(FUSE_PRIVATE_KEY3);
    }

    if (!emmc_storage.initialized) {
        have_keyblobs = false;
    } else if (!emummc_storage_read(KEYBLOB_OFFSET / NX_EMMC_BLOCKSIZE, KB_FIRMWARE_VERSION_600 + 1, keyblob_block)) {
        EPRINTF("Unable to read keyblobs.");
        have_keyblobs = false;
    } else {
        have_keyblobs = true;
    }

    encrypted_keyblob_t *current_keyblob = (encrypted_keyblob_t *)keyblob_block;
    for (u32 i = 0; i <= KB_FIRMWARE_VERSION_600; i++, current_keyblob++) {
        minerva_periodic_training();
        se_aes_crypt_block_ecb(12, DECRYPT, keys->keyblob_key[i], keyblob_key_sources[i]); // temp = unwrap(kbks, tsec)
        se_aes_crypt_block_ecb(14, DECRYPT, keys->keyblob_key[i], keys->keyblob_key[i]); // kbk = unwrap(temp, sbk)
        _load_aes_key(7, keys->keyblob_mac_key[i], keys->keyblob_key[i], keyblob_mac_key_source); // kbm = unwrap(kbms, kbk)
        if (i == 0) {
            se_aes_crypt_block_ecb(7, DECRYPT, keys->device_key, per_console_key_source); // devkey = unwrap(pcks, kbk0)
            se_aes_crypt_block_ecb(7, DECRYPT, keys->device_key_4x, device_master_key_source_kek_source);
        }

        if (!have_keyblobs) {
            continue;
        }

        // verify keyblob is not corrupt
        se_aes_key_set(10, keys->keyblob_mac_key[i], sizeof(keys->keyblob_mac_key[i]));
        se_aes_cmac(10, keyblob_mac, sizeof(keyblob_mac), current_keyblob->iv, sizeof(current_keyblob->iv) + sizeof(keyblob_t));
        if (memcmp(current_keyblob->cmac, keyblob_mac, sizeof(keyblob_mac)) != 0) {
            EPRINTFARGS("Keyblob %x corrupt.", i);
            continue;
        }

        // decrypt keyblobs
        se_aes_key_set(6, keys->keyblob_key[i], sizeof(keys->keyblob_key[i]));
        se_aes_crypt_ctr(6, &keys->keyblob[i], sizeof(keyblob_t), &current_keyblob->key_data, sizeof(keyblob_t), current_keyblob->iv);

        memcpy(keys->package1_key[i], keys->keyblob[i].package1_key, sizeof(keys->package1_key[i]));
        memcpy(keys->master_kek[i], keys->keyblob[i].master_kek, sizeof(keys->master_kek[i]));
        if (!_key_exists(keys->master_key[i])) {
            _load_aes_key(7, keys->master_key[i], keys->master_kek[i], master_key_source);
        }
    }
    free(keyblob_block);
}

static void _derive_bis_keys(key_derivation_ctx_t *keys) {
    minerva_periodic_training();
    u32 generation = fuse_read_odm_keygen_rev();

    if (!(_key_exists(keys->device_key) || (generation && _key_exists(keys->master_key[0]) && _key_exists(keys->device_key_4x)))) {
        return;
    }
    _generate_specific_aes_key(8, keys, &keys->bis_key[0], bis_key_sources[0], generation);
    u32 access_key[AES_128_KEY_SIZE / 4] = {0};
    const u32 option = GET_IS_DEVICE_UNIQUE(IS_DEVICE_UNIQUE);
    _generate_aes_kek(8, keys, access_key, bis_kek_source, generation, option);
    _generate_aes_key(8, keys, keys->bis_key[1], sizeof(keys->bis_key[1]), access_key, bis_key_sources[1]);
    _generate_aes_key(8, keys, keys->bis_key[2], sizeof(keys->bis_key[2]), access_key, bis_key_sources[2]);
    memcpy(keys->bis_key[3], keys->bis_key[2], sizeof(keys->bis_key[3]));
}

static void _derive_non_unique_keys(key_derivation_ctx_t *keys, bool is_dev) {
    if (_key_exists(keys->master_key[0])) {
        const u32 generation = 0;
        const u32 option = GET_IS_DEVICE_UNIQUE(NOT_DEVICE_UNIQUE);
        _generate_aes_kek(8, keys, keys->temp_key, header_kek_source, generation, option);
        _generate_aes_key(8, keys, keys->header_key, sizeof(keys->header_key), keys->temp_key, header_key_source);
    }
}

static void _derive_eticket_rsa_kek(key_derivation_ctx_t *keys, u32 ks, void *out_rsa_kek, const void *kek_source, u32 generation, u32 option) {
    void *access_key = keys->temp_key;
    _generate_aes_kek(ks, keys, access_key, eticket_rsa_kekek_source, generation, option);
    _get_device_unique_data_key(ks, out_rsa_kek, access_key, kek_source);
    
}

static void _derive_ssl_rsa_kek(key_derivation_ctx_t *keys, u32 ks, void *out_rsa_kek, const void *kekek_source, const void *kek_source, u32 generation, u32 option) {
    void *access_key = keys->temp_key;
    _generate_aes_kek(ks, keys, access_key, kekek_source, generation, option);
    _get_device_unique_data_key(ks, out_rsa_kek, access_key, kek_source);
}

static void _derive_misc_keys(key_derivation_ctx_t *keys, bool is_dev) {
    if (_key_exists(keys->device_key) || (_key_exists(keys->master_key[0]) && _key_exists(keys->device_key_4x))) {
        void *access_key = keys->temp_key;
        const u32 generation = 0;
        const u32 option = GET_IS_DEVICE_UNIQUE(IS_DEVICE_UNIQUE);
        _generate_aes_kek(8, keys, access_key, save_mac_kek_source, generation, option);
        _load_aes_key(8, keys->save_mac_key, access_key, save_mac_key_source);
    }

    if (_key_exists(keys->master_key[0])) {
        const void *eticket_kek_source = is_dev ? eticket_rsa_kek_source_dev : eticket_rsa_kek_source;
        const u32 generation = 0;
        u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY);
        _derive_eticket_rsa_kek(keys, 8, keys->eticket_rsa_kek, eticket_kek_source, generation, option);

        const void *ssl_kek_source = is_dev ? ssl_rsa_kek_source_dev : ssl_rsa_kek_source;
        option = SET_SEAL_KEY_INDEX(SEAL_KEY_DECRYPT_DEVICE_UNIQUE_DATA);
        _derive_ssl_rsa_kek(keys, 8, keys->ssl_rsa_kek, ssl_rsa_kekek_source, ssl_kek_source, generation, option);
    }
}

static void _derive_per_generation_keys(key_derivation_ctx_t *keys) {
    for (u32 generation = 0; generation < ARRAY_SIZE(keys->master_key); generation++) {
        if (!_key_exists(keys->master_key[generation]))
            continue;
        for (u32 source_type = 0; source_type < ARRAY_SIZE(key_area_key_sources); source_type++) {
            void *access_key = keys->temp_key;
            const u32 option = GET_IS_DEVICE_UNIQUE(NOT_DEVICE_UNIQUE);
            _generate_aes_kek(8, keys, access_key, key_area_key_sources[source_type], generation + 1, option);
            _load_aes_key(8, keys->key_area_key[source_type][generation], access_key, aes_key_generation_source);
        }
        _load_aes_key(8, keys->package2_key[generation], keys->master_key[generation], package2_key_source);
        _load_aes_key(8, keys->titlekek[generation], keys->master_key[generation], titlekek_source);
    }
}

static bool _get_titlekeys_from_save(u32 buf_size, const u8 *save_mac_key, titlekey_buffer_t *titlekey_buffer, rsa_keypair_t *rsa_keypair) {
    FIL fp;
    u64 br = buf_size;
    u64 offset = 0;
    u32 file_tkey_count = 0;
    u32 save_x = gfx_con.x, save_y = gfx_con.y;
    bool is_personalized = rsa_keypair != NULL;
    u32 start_titlekey_count = _titlekey_count;
    char titlekey_save_path[32] = "bis:/save/80000000000000E1";

    if (is_personalized) {
        titlekey_save_path[25] = '2';
        gfx_printf("\n%kPersonalized... ", colors[color_idx % 6]);
    } else {
        gfx_printf("\n%kCommon...       ", colors[color_idx % 6]);
    }

    if (f_open(&fp, titlekey_save_path, FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open e1 save. Skipping.");
        return false;
    }

    save_ctx_t *save_ctx = calloc(1, sizeof(save_ctx_t));
    save_init(save_ctx, &fp, save_mac_key, 0);

    bool save_process_success = save_process(save_ctx);
    TPRINTF("\n  Save process...");

    if (!save_process_success) {
        EPRINTF("Failed to process es save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    const char ticket_bin_path[32] = "/ticket.bin";
    const char ticket_list_bin_path[32] = "/ticket_list.bin";
    save_data_file_ctx_t ticket_file;

    if (!save_open_file(save_ctx, &ticket_file, ticket_list_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket_list.bin in save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    bool terminator_reached = false;
    while (offset < ticket_file.size && !terminator_reached) {
        if (!save_data_file_read(&ticket_file, &br, offset, titlekey_buffer->read_buffer, buf_size) || titlekey_buffer->read_buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        minerva_periodic_training();
        ticket_record_t *curr_ticket_record = (ticket_record_t *)titlekey_buffer->read_buffer;
        for (u32 i = 0; i < buf_size; i += sizeof(ticket_record_t), curr_ticket_record++) {
            if (curr_ticket_record->rights_id[0] == 0xFF) {
                terminator_reached = true;
                break;
            }
            file_tkey_count++;
        }
    }
    TPRINTF("  Count keys...");

    if (!save_open_file(save_ctx, &ticket_file, ticket_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket.bin in save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    if (is_personalized) {
        se_rsa_key_set(0, rsa_keypair->modulus, sizeof(rsa_keypair->modulus), rsa_keypair->private_exponent, sizeof(rsa_keypair->private_exponent));
    }

    const u32 ticket_sig_type_rsa2048_sha256 = 0x10004;

    offset = 0;
    terminator_reached = false;
    u32 pct = 0, last_pct = 0, i = 0;
    while (offset < ticket_file.size && !terminator_reached) {
        if (!save_data_file_read(&ticket_file, &br, offset, titlekey_buffer->read_buffer, buf_size) || titlekey_buffer->read_buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        ticket_t *curr_ticket = (ticket_t *)titlekey_buffer->read_buffer;
        for (u32 j = 0; j < buf_size; j += sizeof(ticket_t), curr_ticket++) {
            minerva_periodic_training();
            pct = (_titlekey_count - start_titlekey_count) * 100 / file_tkey_count;
            if (pct > last_pct && pct <= 100) {
                last_pct = pct;
                tui_pbar(save_x, save_y, pct, COLOR_GREEN, 0xFF155500);
            }
            if (i == file_tkey_count || curr_ticket->signature_type == 0) {
                terminator_reached = true;
                break;
            }
            if (curr_ticket->signature_type != ticket_sig_type_rsa2048_sha256) {
                i++;
                continue;
            }
            if (is_personalized) {
                se_rsa_exp_mod(0, curr_ticket->titlekey_block, sizeof(curr_ticket->titlekey_block), curr_ticket->titlekey_block, sizeof(curr_ticket->titlekey_block));
                if (se_rsa_oaep_decode(
                        curr_ticket->titlekey_block, sizeof(titlekey_buffer->titlekeys[0]),
                        null_hash, sizeof(null_hash),
                        curr_ticket->titlekey_block, sizeof(curr_ticket->titlekey_block)
                    ) != sizeof(titlekey_buffer->titlekeys[0])
                )
                    continue;
            }
            memcpy(titlekey_buffer->rights_ids[_titlekey_count], curr_ticket->rights_id, sizeof(titlekey_buffer->rights_ids[0]));
            memcpy(titlekey_buffer->titlekeys[_titlekey_count], curr_ticket->titlekey_block, sizeof(titlekey_buffer->titlekeys[0]));
            _titlekey_count++;
            i++;
        }
    }
    tui_pbar(save_x, save_y, 100, COLOR_GREEN, 0xFF155500);
    f_close(&fp);
    save_free_contexts(save_ctx);
    free(save_ctx);

    gfx_con_setpos(0, save_y);

    if (is_personalized) {
        TPRINTFARGS("\n%kPersonalized... ", colors[(color_idx++) % 6]);
    } else {
        TPRINTFARGS("\n%kCommon...       ", colors[(color_idx++) % 6]);
    }

    gfx_printf("\n\n\n");

    return true;
}

static bool _derive_sd_seed(key_derivation_ctx_t *keys) {
    FIL fp;
    u32 read_bytes = 0;
    char *private_path = malloc(200);
    strcpy(private_path, "sd:/");

    if (emu_cfg.nintendo_path && (emu_cfg.enabled || !h_cfg.emummc_force_disable)) {
        strcat(private_path, emu_cfg.nintendo_path);
    } else {
        strcat(private_path, "Nintendo");
    }
    strcat(private_path, "/Contents/private");
    FRESULT fr = f_open(&fp, private_path, FA_READ | FA_OPEN_EXISTING);
    free(private_path);
    if (fr) {
        EPRINTF("Unable to open SD seed vector. Skipping.");
        return false;
    }
    // get sd seed verification vector
    if (f_read(&fp, keys->temp_key, AES_128_KEY_SIZE, &read_bytes) || read_bytes != AES_128_KEY_SIZE) {
        EPRINTF("Unable to read SD seed vector. Skipping.");
        f_close(&fp);
        return false;
    }
    f_close(&fp);

    // this file is small enough that parsing the savedata properly is slower
    if (f_open(&fp, "bis:/save/8000000000000043", FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open ns_appman save.\nSkipping SD seed.");
        return false;
    }

    u8 read_buf[0x20] __attribute__((aligned(4))) = {0};
    for (u32 i = SZ_32K; i < f_size(&fp); i += SZ_16K) {
        if (f_lseek(&fp, i) || f_read(&fp, read_buf, 0x20, &read_bytes) || read_bytes != 0x20)
            break;
        if (!memcmp(keys->temp_key, read_buf, sizeof(keys->temp_key))) {
            memcpy(keys->sd_seed, read_buf + 0x10, sizeof(keys->sd_seed));
            break;
        }
    }
    f_close(&fp);

    TPRINTFARGS("%kSD Seed...      ", colors[(color_idx++) % 6]);

    return true;
}

static bool _read_cal0(void *read_buffer) {
    if (!emummc_storage_read(NX_EMMC_CALIBRATION_OFFSET / NX_EMMC_BLOCKSIZE, NX_EMMC_CALIBRATION_SIZE / NX_EMMC_BLOCKSIZE, read_buffer)) {
        EPRINTF("Unable to read PRODINFO.");
        return false;
    }

    se_aes_xts_crypt(1, 0, DECRYPT, 0, read_buffer, read_buffer, XTS_CLUSTER_SIZE, NX_EMMC_CALIBRATION_SIZE / XTS_CLUSTER_SIZE);

    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)read_buffer;
    if (cal0->magic != MAGIC_CAL0) {
        EPRINTF("Invalid CAL0 magic. Check BIS key 0.");
        return false;
    }

    return true;
}

static bool _get_rsa_ssl_key(const nx_emmc_cal0_t *cal0, const void **out_key, u32 *out_key_size, const void **out_iv, u32 *out_generation) {
    const u32 ext_key_size = sizeof(cal0->ext_ssl_key_iv) + sizeof(cal0->ext_ssl_key);
    const u32 ext_key_crc_size = ext_key_size + sizeof(cal0->ext_ssl_key_ver) + sizeof(cal0->crc16_pad39);
    const u32 key_size = sizeof(cal0->ssl_key_iv) + sizeof(cal0->ssl_key);
    const u32 key_crc_size = key_size + sizeof(cal0->crc16_pad18);

    if (cal0->ext_ssl_key_crc == crc16_calc(cal0->ext_ssl_key_iv, ext_key_crc_size)) {
        *out_key = cal0->ext_ssl_key;
        *out_key_size = ext_key_size;
        *out_iv = cal0->ext_ssl_key_iv;
        // settings sysmodule manually zeroes this out below cal version 9
        *out_generation = cal0->version <= 8 ? 0 : cal0->ext_ssl_key_ver;
    } else if (cal0->ssl_key_crc == crc16_calc(cal0->ssl_key_iv, key_crc_size)) {
        *out_key = cal0->ssl_key;
        *out_key_size = key_size;
        *out_iv = cal0->ssl_key_iv;
        *out_generation = 0;
    } else {
        return false;
    }
    return true;
}

static bool _derive_personalized_ssl_key(key_derivation_ctx_t *keys, titlekey_buffer_t *titlekey_buffer) {
    if (!_read_cal0(titlekey_buffer->read_buffer)) {
        return false;
    }

    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)titlekey_buffer->read_buffer;
    u32 keypair_generation = 0;
    const void *ssl_device_key = NULL;
    const void *ssl_iv = NULL;
    u32 key_size = 0;
    void *keypair_ctr_key = NULL;
    bool enforce_unique = true;

    if (!_get_rsa_ssl_key(cal0, &ssl_device_key, &key_size, &ssl_iv, &keypair_generation)) {
        EPRINTF("Crc16 error reading device key.");
        return false;
    }

    if (key_size == SSL_RSA_KEYPAIR_SIZE) {
        bool all_zero = true;
        const u8 *key8 = (const u8 *)ssl_device_key;
        for (u32 i = RSA_2048_KEY_SIZE; i < SSL_RSA_KEYPAIR_SIZE; i++) {
            if (key8[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            // keypairs of this form are not encrypted
            memcpy(keys->ssl_rsa_keypair, ssl_device_key, RSA_2048_KEY_SIZE);
            return true;
        }

        u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_DECRYPT_DEVICE_UNIQUE_DATA);
        keypair_ctr_key = keys->ssl_rsa_kek_legacy;
        _derive_ssl_rsa_kek(keys, 7, keypair_ctr_key, ssl_rsa_kekek_source, ssl_rsa_kek_source_legacy, keypair_generation, option);
        enforce_unique = false;
    }

    if (keypair_generation) {
        u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_SSL_KEY) | IS_DEVICE_UNIQUE;
        keypair_ctr_key = keys->ssl_rsa_kek_personalized;
        _derive_ssl_rsa_kek(keys, 7, keypair_ctr_key, ssl_client_cert_kek_source, ssl_client_cert_key_source, keypair_generation, option);
    } else {
        keypair_ctr_key = keys->ssl_rsa_kek;
    }

    u32 ctr_size = enforce_unique ? key_size - 0x20 : key_size - 0x10;
    se_aes_key_set(6, keypair_ctr_key, AES_128_KEY_SIZE);
    se_aes_crypt_ctr(6, keys->ssl_rsa_keypair, ctr_size, ssl_device_key, ctr_size, ssl_iv);

    if (enforce_unique) {
        u32 j_block[AES_128_KEY_SIZE / 4] = {0};
        se_aes_key_set(7, keypair_ctr_key, AES_128_KEY_SIZE);
        _ghash(7, j_block, ssl_iv, 0x10, NULL, false);

        u32 calc_mac[AES_128_KEY_SIZE / 4] = {0};
        _ghash(7, calc_mac, keys->ssl_rsa_keypair, ctr_size, j_block, true);

        const u8 *key8 = (const u8 *)ssl_device_key;
        if (memcmp(calc_mac, &key8[ctr_size], 0x10) != 0) {
            EPRINTF("SSL keypair has invalid GMac.");
            memset(keys->ssl_rsa_keypair, 0, sizeof(keys->ssl_rsa_keypair));
            return false;
        }
    }

    return true;
}

static bool _get_rsa_eticket_key(const nx_emmc_cal0_t *cal0, const void **out_key, const void **out_iv, u32 *out_generation) {
    const u32 ext_key_size = sizeof(cal0->ext_ecc_rsa2048_eticket_key_iv) + sizeof(cal0->ext_ecc_rsa2048_eticket_key);
    const u32 ext_key_crc_size = ext_key_size + sizeof(cal0->ext_ecc_rsa2048_eticket_key_ver) + sizeof(cal0->crc16_pad38);
    const u32 key_size = sizeof(cal0->rsa2048_eticket_key_iv) + sizeof(cal0->rsa2048_eticket_key);
    const u32 key_crc_size = key_size + sizeof(cal0->crc16_pad21);

    if (cal0->ext_ecc_rsa2048_eticket_key_crc == crc16_calc(cal0->ext_ecc_rsa2048_eticket_key_iv, ext_key_crc_size)) {
        *out_key = cal0->ext_ecc_rsa2048_eticket_key;
        *out_iv = cal0->ext_ecc_rsa2048_eticket_key_iv;
        // settings sysmodule manually zeroes this out below cal version 9
        *out_generation = cal0->version <= 8 ? 0 : cal0->ext_ecc_rsa2048_eticket_key_ver;
    } else if (cal0->rsa2048_eticket_key_crc == crc16_calc(cal0->rsa2048_eticket_key_iv, key_crc_size)) {
        *out_key = cal0->rsa2048_eticket_key;
        *out_iv = cal0->rsa2048_eticket_key_iv;
        *out_generation = 0;
    } else {
        return false;
    }
    return true;
}

static bool _derive_titlekeys(key_derivation_ctx_t *keys, titlekey_buffer_t *titlekey_buffer, bool is_dev) {
    if (!_key_exists(keys->eticket_rsa_kek)) {
        return false;
    }

    gfx_printf("%kTitlekeys...     \n", colors[(color_idx++) % 6]);

    if (!_read_cal0(titlekey_buffer->read_buffer)) {
        return false;
    }

    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)titlekey_buffer->read_buffer;
    u32 keypair_generation = 0;
    const void *eticket_device_key = NULL;
    const void *eticket_iv = NULL;
    void *keypair_ctr_key = NULL;

    if (!_get_rsa_eticket_key(cal0, &eticket_device_key, &eticket_iv, &keypair_generation)) {
        EPRINTF("Crc16 error reading device key.");
        return false;
    }

    if (keypair_generation) {
        u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY) | IS_DEVICE_UNIQUE;
        _derive_eticket_rsa_kek(keys, 7, keys->eticket_rsa_kek_personalized, is_dev ? eticket_rsa_kek_source_dev : eticket_rsa_kek_source, keypair_generation, option);
        keypair_ctr_key = keys->eticket_rsa_kek_personalized;
    } else {
        keypair_ctr_key = keys->eticket_rsa_kek;
    }

    se_aes_key_set(6, keypair_ctr_key, AES_128_KEY_SIZE);
    se_aes_crypt_ctr(6, &keys->eticket_rsa_keypair, sizeof(keys->eticket_rsa_keypair), eticket_device_key, sizeof(keys->eticket_rsa_keypair), eticket_iv);

    if (_read_be_u32(keys->eticket_rsa_keypair.public_exponent, 0) != RSA_PUBLIC_EXPONENT) {
        // try legacy kek source
        u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY);
        keypair_ctr_key = keys->temp_key;
        _derive_eticket_rsa_kek(keys, 7, keypair_ctr_key, eticket_rsa_kek_source_legacy, 0, option);

        se_aes_key_set(6, keypair_ctr_key, AES_128_KEY_SIZE);
        se_aes_crypt_ctr(6, &keys->eticket_rsa_keypair, sizeof(keys->eticket_rsa_keypair), eticket_device_key, sizeof(keys->eticket_rsa_keypair), eticket_iv);

        if (_read_be_u32(keys->eticket_rsa_keypair.public_exponent, 0) != RSA_PUBLIC_EXPONENT) {
            EPRINTF("Invalid public exponent.");
            memset(&keys->eticket_rsa_keypair, 0, sizeof(keys->eticket_rsa_keypair));
            return false;
        } else {
            memcpy(keys->eticket_rsa_kek, keys->temp_key, sizeof(keys->eticket_rsa_kek));
        }
    }

    if (!_test_key_pair(keys->eticket_rsa_keypair.public_exponent, keys->eticket_rsa_keypair.private_exponent, keys->eticket_rsa_keypair.modulus)) {
        EPRINTF("Invalid keypair. Check eticket_rsa_kek.");
        memset(&keys->eticket_rsa_keypair, 0, sizeof(keys->eticket_rsa_keypair));
        return false;
    }

    const u32 buf_size = SZ_16K;
    _get_titlekeys_from_save(buf_size, keys->save_mac_key, titlekey_buffer, NULL);
    _get_titlekeys_from_save(buf_size, keys->save_mac_key, titlekey_buffer, &keys->eticket_rsa_keypair);

    gfx_printf("\n%k  Found %d titlekeys.\n\n", colors[(color_idx++) % 6], _titlekey_count);

    return true;
}

static bool _derive_emmc_keys(key_derivation_ctx_t *keys, titlekey_buffer_t *titlekey_buffer, bool is_dev) {
    // Set BIS keys.
    // PRODINFO/PRODINFOF
    se_aes_key_set(0, keys->bis_key[0] + 0x00, AES_128_KEY_SIZE);
    se_aes_key_set(1, keys->bis_key[0] + 0x10, AES_128_KEY_SIZE);
    // SAFE
    se_aes_key_set(2, keys->bis_key[1] + 0x00, AES_128_KEY_SIZE);
    se_aes_key_set(3, keys->bis_key[1] + 0x10, AES_128_KEY_SIZE);
    // SYSTEM/USER
    se_aes_key_set(4, keys->bis_key[2] + 0x00, AES_128_KEY_SIZE);
    se_aes_key_set(5, keys->bis_key[2] + 0x10, AES_128_KEY_SIZE);

    if (!emummc_storage_set_mmc_partition(EMMC_GPP)) {
        EPRINTF("Unable to set partition.");
        return false;
    }
    // Parse eMMC GPT.
    LIST_INIT(gpt);
    nx_emmc_gpt_parse(&gpt, &emmc_storage);

    emmc_part_t *system_part = nx_emmc_part_find(&gpt, "SYSTEM");
    if (!system_part) {
        EPRINTF("Unable to locate System partition.");
        nx_emmc_gpt_free(&gpt);
        return false;
    }

    nx_emmc_bis_init(system_part);

    if (f_mount(&emmc_fs, "bis:", 1)) {
        EPRINTF("Unable to mount system partition.");
        nx_emmc_gpt_free(&gpt);
        return false;
    }

    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
    } else if (!_derive_sd_seed(keys)) {
        EPRINTF("Unable to get SD seed.");
    }

    bool res = _derive_titlekeys(keys, titlekey_buffer, is_dev);
    if (!res) {
        EPRINTF("Unable to derive titlekeys.");
    }

    _derive_personalized_ssl_key(keys, titlekey_buffer);

    f_mount(NULL, "bis:", 1);
    nx_emmc_gpt_free(&gpt);

    return res;
}

// The security engine supports partial key override for locked keyslots
// This allows for a manageable brute force on a PC
// Then the Mariko AES class keys, KEK, BEK, unique SBK and SSK can be recovered
int save_mariko_partial_keys(u32 start, u32 count, bool append) {
    const char *keyfile_path = "sd:/switch/partialaes.keys";
    if (!f_stat(keyfile_path, NULL)) {
        f_unlink(keyfile_path);
    }

    if (start + count > SE_AES_KEYSLOT_COUNT) {
        return 1;
    }

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_partial_grey(0x1B, 32, 1224);
    gfx_con_setpos(0, 32);

    color_idx = 0;

    u32 pos = 0;
    u32 zeros[AES_128_KEY_SIZE / 4] = {0};
    u8 *data = malloc(4 * AES_128_KEY_SIZE);
    char *text_buffer = calloc(1, 0x100 * count);

    for (u32 ks = start; ks < start + count; ks++) {
        // Check if key is as expected
        if (ks < ARRAY_SIZE(mariko_key_vectors)) {
            se_aes_crypt_block_ecb(ks, DECRYPT, &data[0], mariko_key_vectors[ks]);
            if (_key_exists(data)) {
                EPRINTFARGS("Failed to validate keyslot %d.", ks);
                continue;
            }
        }

        // Encrypt zeros with complete key
        se_aes_crypt_block_ecb(ks, ENCRYPT, &data[3 * AES_128_KEY_SIZE], zeros);

        // We only need to overwrite 3 of the dwords of the key
        for (u32 i = 0; i < 3; i++) {
            // Overwrite ith dword of key with zeros
            se_aes_key_partial_set(ks, i, 0);
            // Encrypt zeros with more of the key zeroed out
            se_aes_crypt_block_ecb(ks, ENCRYPT, &data[(2 - i) * AES_128_KEY_SIZE], zeros);
        }

        // Skip saving key if two results are the same indicating unsuccessful overwrite or empty slot
        if (memcmp(&data[0], &data[SE_KEY_128_SIZE], AES_128_KEY_SIZE) == 0) {
            EPRINTFARGS("Failed to overwrite keyslot %d.", ks);
            continue;
        }

        pos += s_printf(&text_buffer[pos], "%d\n", ks);
        for (u32 i = 0; i < 4; i++) {
            for (u32 j = 0; j < AES_128_KEY_SIZE; j++)
                pos += s_printf(&text_buffer[pos], "%02x", data[i * AES_128_KEY_SIZE + j]);
            pos += s_printf(&text_buffer[pos], " ");
        }
        pos += s_printf(&text_buffer[pos], "\n");
    }
    free(data);

    if (strlen(text_buffer) == 0) {
        EPRINTFARGS("Failed to dump partial keys %d-%d.", start, start + count - 1);
        free(text_buffer);
        return 2;
    }

    FIL fp;
    BYTE mode = FA_WRITE;

    if (append) {
        mode |= FA_OPEN_APPEND;
    } else {
        mode |= FA_CREATE_ALWAYS;
    }

    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
        free(text_buffer);
        return 3;
    }

    if (f_open(&fp, keyfile_path, mode)) {
        EPRINTF("Unable to write partial keys to SD.");
        free(text_buffer);
        return 3;
    }

    f_write(&fp, text_buffer, strlen(text_buffer), NULL);
    f_close(&fp);

    gfx_printf("%kWrote partials to %s\n", colors[(color_idx++) % 6], keyfile_path);

    free(text_buffer);

    return 0;
}

static void _save_keys_to_sd(key_derivation_ctx_t *keys, titlekey_buffer_t *titlekey_buffer, bool is_dev) {
    char *text_buffer = NULL;
    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
        return;
    }

    u32 text_buffer_size = MAX(_titlekey_count * sizeof(titlekey_text_buffer_t) + 1, SZ_16K);
    text_buffer = (char *)calloc(1, text_buffer_size);

    SAVE_KEY(aes_kek_generation_source);
    SAVE_KEY(aes_key_generation_source);
    SAVE_KEY(bis_kek_source);
    SAVE_KEY_FAMILY_VAR(bis_key, keys->bis_key, 0);
    SAVE_KEY_FAMILY_VAR(bis_key_source, bis_key_sources, 0);
    SAVE_KEY_VAR(device_key, keys->device_key);
    SAVE_KEY_VAR(device_key_4x, keys->device_key_4x);
    SAVE_KEY_VAR(eticket_rsa_kek, keys->eticket_rsa_kek);
    SAVE_KEY_VAR(eticket_rsa_kek_personalized, keys->eticket_rsa_kek_personalized);
    if (is_dev) {
        SAVE_KEY_VAR(eticket_rsa_kek_source, eticket_rsa_kek_source_dev);
    } else {
        SAVE_KEY(eticket_rsa_kek_source);
    }
    SAVE_KEY(eticket_rsa_kekek_source);
    _save_key("eticket_rsa_keypair", &keys->eticket_rsa_keypair, sizeof(keys->eticket_rsa_keypair), text_buffer);
    SAVE_KEY(header_kek_source);
    SAVE_KEY_VAR(header_key, keys->header_key);
    SAVE_KEY(header_key_source);
    SAVE_KEY_FAMILY_VAR(key_area_key_application, keys->key_area_key[0], 0);
    SAVE_KEY_VAR(key_area_key_application_source, key_area_key_sources[0]);
    SAVE_KEY_FAMILY_VAR(key_area_key_ocean, keys->key_area_key[1], 0);
    SAVE_KEY_VAR(key_area_key_ocean_source, key_area_key_sources[1]);
    SAVE_KEY_FAMILY_VAR(key_area_key_system, keys->key_area_key[2], 0);
    SAVE_KEY_VAR(key_area_key_system_source, key_area_key_sources[2]);
    SAVE_KEY_FAMILY_VAR(keyblob, keys->keyblob, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_key, keys->keyblob_key, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_key_source, keyblob_key_sources, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_mac_key, keys->keyblob_mac_key, 0);
    SAVE_KEY(keyblob_mac_key_source);
    if (is_dev) {
        SAVE_KEY_FAMILY_VAR(mariko_master_kek_source, mariko_master_kek_sources_dev, 5);
    } else {
        SAVE_KEY_FAMILY_VAR(mariko_master_kek_source, mariko_master_kek_sources, 5);
    }
    SAVE_KEY_FAMILY_VAR(master_kek, keys->master_kek, 0);
    SAVE_KEY_FAMILY_VAR(master_kek_source, master_kek_sources, KB_FIRMWARE_VERSION_620);
    SAVE_KEY_FAMILY_VAR(master_key, keys->master_key, 0);
    SAVE_KEY(master_key_source);
    SAVE_KEY_FAMILY_VAR(package1_key, keys->package1_key, 0);
    SAVE_KEY_FAMILY_VAR(package2_key, keys->package2_key, 0);
    SAVE_KEY(package2_key_source);
    SAVE_KEY(per_console_key_source);
    SAVE_KEY(retail_specific_aes_key_source);
    SAVE_KEY(save_mac_kek_source);
    SAVE_KEY_VAR(save_mac_key, keys->save_mac_key);
    SAVE_KEY(save_mac_key_source);
    SAVE_KEY(save_mac_sd_card_kek_source);
    SAVE_KEY(save_mac_sd_card_key_source);
    SAVE_KEY(sd_card_custom_storage_key_source);
    SAVE_KEY(sd_card_kek_source);
    SAVE_KEY(sd_card_nca_key_source);
    SAVE_KEY(sd_card_save_key_source);
    SAVE_KEY_VAR(sd_seed, keys->sd_seed);
    SAVE_KEY_VAR(secure_boot_key, keys->sbk);
    SAVE_KEY_VAR(ssl_rsa_kek, keys->ssl_rsa_kek);
    SAVE_KEY_VAR(ssl_rsa_kek_personalized, keys->ssl_rsa_kek_personalized);
    if (is_dev) {
        SAVE_KEY_VAR(ssl_rsa_kek_source, ssl_rsa_kek_source_dev);
    } else {
        SAVE_KEY(ssl_rsa_kek_source);
    }
    SAVE_KEY(ssl_rsa_kekek_source);
    _save_key("ssl_rsa_keypair", keys->ssl_rsa_keypair, RSA_2048_KEY_SIZE, text_buffer);
    SAVE_KEY_FAMILY_VAR(titlekek, keys->titlekek, 0);
    SAVE_KEY(titlekek_source);
    SAVE_KEY_VAR(tsec_key, keys->tsec_key);

    const u32 root_key_ver = 2;
    char root_key_name[21] = "tsec_root_key_00";
    s_printf(root_key_name + 14, "%02x", root_key_ver);
    _save_key(root_key_name, keys->tsec_root_key, AES_128_KEY_SIZE, text_buffer);

    gfx_printf("\n%k  Found %d %s keys.\n\n", colors[(color_idx++) % 6], _key_count, is_dev ? "dev" : "prod");
    gfx_printf("%kFound through master_key_%02x.\n\n", colors[(color_idx++) % 6], KB_FIRMWARE_VERSION_MAX);

    f_mkdir("sd:/switch");

    const char *keyfile_path = is_dev ? "sd:/switch/dev.keys" : "sd:/switch/prod.keys";

    FILINFO fno;
    if (!sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
    } else {
        EPRINTF("Unable to save keys to SD.");
    }

    if (_titlekey_count == 0 || !titlekey_buffer) {
        free(text_buffer);
        return;
    }
    memset(text_buffer, 0, text_buffer_size);

    titlekey_text_buffer_t *titlekey_text = (titlekey_text_buffer_t *)text_buffer;

    for (u32 i = 0; i < _titlekey_count; i++) {
        for (u32 j = 0; j < AES_128_KEY_SIZE; j++)
            s_printf(&titlekey_text[i].rights_id[j * 2], "%02x", titlekey_buffer->rights_ids[i][j]);
        s_printf(titlekey_text[i].equals, " = ");
        for (u32 j = 0; j < AES_128_KEY_SIZE; j++)
            s_printf(&titlekey_text[i].titlekey[j * 2], "%02x", titlekey_buffer->titlekeys[i][j]);
        s_printf(titlekey_text[i].newline, "\n");
    }

    keyfile_path = "sd:/switch/title.keys";
    if (!sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
    } else {
        EPRINTF("Unable to save titlekeys to SD.");
    }

    free(text_buffer);
}

static bool _check_keyslot_access() {
    u8 test_data[AES_128_KEY_SIZE] = {0};
    const u8 test_ciphertext[AES_128_KEY_SIZE] = {0};
    se_aes_key_set(8, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(8, DECRYPT, test_data, test_ciphertext);

    return memcmp(test_data, "\x7b\x1d\x29\xa1\x6c\xf8\xcc\xab\x84\xf0\xb8\xa5\x98\xe4\x2f\xa6", SE_KEY_128_SIZE) == 0;
}

static void _derive_master_keys(key_derivation_ctx_t *prod_keys, key_derivation_ctx_t *dev_keys, bool is_dev) {
    key_derivation_ctx_t *keys = is_dev ? dev_keys : prod_keys;

    if (h_cfg.t210b01) {
        _derive_master_key_mariko(keys, is_dev);
        minerva_periodic_training();
        _derive_master_keys_from_latest_key(keys, is_dev);
    } else {
        int res = _run_ams_keygen(keys);
        if (res) {
            return;
        }

        u8 *aes_keys = (u8 *)calloc(SZ_4K, 1);
        se_get_aes_keys(aes_keys + SZ_2K, aes_keys, AES_128_KEY_SIZE);
        memcpy(&dev_keys->tsec_root_key, aes_keys + 11 * AES_128_KEY_SIZE, AES_128_KEY_SIZE);
        memcpy(keys->tsec_key, aes_keys + 12 * AES_128_KEY_SIZE, AES_128_KEY_SIZE);
        memcpy(&prod_keys->tsec_root_key, aes_keys + 13 * AES_128_KEY_SIZE, AES_128_KEY_SIZE);
        free(aes_keys);

        _derive_master_keys_from_latest_key(prod_keys, false);
        minerva_periodic_training();
        _derive_master_keys_from_latest_key(dev_keys, true);
        minerva_periodic_training();
        _derive_keyblob_keys(keys);
    }
}

static void _derive_keys() {
    minerva_periodic_training();

    if (!_check_keyslot_access()) {
        EPRINTF("Unable to set crypto keyslots!\nTry launching payload differently\n or flash Spacecraft-NX if using a modchip.");
        return;
    }

    u32 start_whole_operation_time = get_tmr_us();

    if (emummc_storage_init_mmc()) {
        EPRINTF("Unable to init MMC.");
    } else {
        TPRINTFARGS("%kMMC init...     ", colors[(color_idx++) % 6]);
    }

    minerva_periodic_training();

    if (emmc_storage.initialized && !emummc_storage_set_mmc_partition(EMMC_BOOT0)) {
        EPRINTF("Unable to set partition.");
        emummc_storage_end();
    }

    bool is_dev = fuse_read_hw_state() == FUSE_NX_HW_STATE_DEV;

    key_derivation_ctx_t __attribute__((aligned(4))) prod_keys = {0}, dev_keys = {0};
    key_derivation_ctx_t *keys = is_dev ? &dev_keys : &prod_keys;

    _derive_master_keys(&prod_keys, &dev_keys, is_dev);

    TPRINTFARGS("%kMaster keys...  ", colors[(color_idx++) % 6]);

    _derive_bis_keys(keys);

    TPRINTFARGS("%kBIS keys...     ", colors[(color_idx++) % 6]);

    minerva_periodic_training();
    _derive_misc_keys(keys, is_dev);

    minerva_periodic_training();
    _derive_non_unique_keys(&prod_keys, is_dev);

    minerva_periodic_training();
    _derive_non_unique_keys(&dev_keys, is_dev);

    minerva_periodic_training();
    _derive_per_generation_keys(&prod_keys);

    minerva_periodic_training();
    _derive_per_generation_keys(&dev_keys);

    titlekey_buffer_t *titlekey_buffer = (titlekey_buffer_t *)TITLEKEY_BUF_ADR;

    // Requires BIS key for SYSTEM partition
    if (!emmc_storage.initialized) {
        EPRINTF("eMMC not initialized.\nSkipping SD seed and titlekeys.");
    } else if (_key_exists(keys->bis_key[2])) {
        _derive_emmc_keys(keys, titlekey_buffer, is_dev);
    } else {
        EPRINTF("Missing needed BIS keys.\nSkipping SD seed and titlekeys.");
    }

    end_time = get_tmr_us();
    gfx_printf("%kLockpick totally done in %d us\n", colors[(color_idx++) % 6], end_time - start_whole_operation_time);

    if (h_cfg.t210b01) {
        // On Mariko, save only relevant key set
        _save_keys_to_sd(keys, titlekey_buffer, is_dev);
    } else {
        // On Erista, save both prod and dev key sets
        _save_keys_to_sd(&prod_keys, titlekey_buffer, false);
        _key_count = 0;
        _save_keys_to_sd(&dev_keys, NULL, true);
    }
}

void derive_amiibo_keys() {
    minerva_change_freq(FREQ_1600);

    bool is_dev = fuse_read_hw_state() == FUSE_NX_HW_STATE_DEV;

    key_derivation_ctx_t __attribute__((aligned(4))) prod_keys = {0}, dev_keys = {0};
    key_derivation_ctx_t *keys = is_dev ? &dev_keys : &prod_keys;
    const u8 *encrypted_keys = is_dev ? encrypted_nfc_keys_dev : encrypted_nfc_keys;

    _derive_master_keys(&prod_keys, &dev_keys, is_dev);

    minerva_periodic_training();

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_partial_grey(0x1B, 32, 1224);
    gfx_con_setpos(0, 32);

    color_idx = 0;

    minerva_periodic_training();

    if (!_key_exists(keys->master_key[0])) {
        EPRINTF("Unable to derive master keys for NFC.");
        minerva_change_freq(FREQ_800);
        btn_wait();
        return;
    }

    _decrypt_aes_key(8, keys, keys->temp_key, nfc_key_source, 0, 0);

    nfc_keyblob_t __attribute__((aligned(4))) nfc_keyblob;
    static const u8 nfc_iv[AES_128_KEY_SIZE] = {
        0xB9, 0x1D, 0xC1, 0xCF, 0x33, 0x5F, 0xA6, 0x13, 0x2A, 0xEF, 0x90, 0x99, 0xAA, 0xCA, 0x93, 0xC8};
    se_aes_key_set(6, keys->temp_key, AES_128_KEY_SIZE);
    se_aes_crypt_ctr(6, &nfc_keyblob, sizeof(nfc_keyblob), encrypted_keys, sizeof(nfc_keyblob), &nfc_iv);

    minerva_periodic_training();

    u8 xor_pad[0x20] __attribute__((aligned(4))) = {0};
    se_aes_key_set(6, nfc_keyblob.ctr_key, AES_128_KEY_SIZE);
    se_aes_crypt_ctr(6, xor_pad, sizeof(xor_pad), xor_pad, sizeof(xor_pad), nfc_keyblob.ctr_iv);

    minerva_periodic_training();

    nfc_save_key_t __attribute__((aligned(4))) nfc_save_keys[2] = {0};
    memcpy(nfc_save_keys[0].hmac_key, nfc_keyblob.hmac_key, sizeof(nfc_keyblob.hmac_key));
    memcpy(nfc_save_keys[0].phrase, nfc_keyblob.phrase, sizeof(nfc_keyblob.phrase));
    nfc_save_keys[0].seed_size = sizeof(nfc_keyblob.seed);
    memcpy(nfc_save_keys[0].seed, nfc_keyblob.seed, sizeof(nfc_keyblob.seed));
    memcpy(nfc_save_keys[0].xor_pad, xor_pad, sizeof(xor_pad));

    memcpy(nfc_save_keys[1].hmac_key, nfc_keyblob.hmac_key_for_verif, sizeof(nfc_keyblob.hmac_key_for_verif));
    memcpy(nfc_save_keys[1].phrase, nfc_keyblob.phrase_for_verif, sizeof(nfc_keyblob.phrase_for_verif));
    nfc_save_keys[1].seed_size = sizeof(nfc_keyblob.seed_for_verif);
    memcpy(nfc_save_keys[1].seed, nfc_keyblob.seed_for_verif, sizeof(nfc_keyblob.seed_for_verif));
    memcpy(nfc_save_keys[1].xor_pad, xor_pad, sizeof(xor_pad));

    minerva_periodic_training();

    u8 hash[0x20] = {0};
    se_calc_sha256_oneshot(hash, &nfc_save_keys[0], sizeof(nfc_save_keys));

    if (memcmp(hash, is_dev ? nfc_blob_hash_dev : nfc_blob_hash, sizeof(hash)) != 0) {
        EPRINTF("Amiibo hash mismatch. Skipping save.");
        minerva_change_freq(FREQ_800);
        btn_wait();
        return;
    }

    const char *keyfile_path = is_dev ? "sd:/switch/key_dev.bin" : "sd:/switch/key_retail.bin";

    if (!sd_save_to_file(&nfc_save_keys[0], sizeof(nfc_save_keys), keyfile_path)) {
        gfx_printf("%kWrote Amiibo keys to\n %s\n", colors[(color_idx++) % 6], keyfile_path);
    } else {
        EPRINTF("Unable to save Amiibo keys to SD.");
    }

    gfx_printf("\n%kPress a button to return to the menu.", colors[(color_idx++) % 6]);
    minerva_change_freq(FREQ_800);
    btn_wait();
    gfx_clear_grey(0x1B);
}

void dump_keys() {
    minerva_change_freq(FREQ_1600);

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_grey(0x1B);
    gfx_con_setpos(0, 0);

    gfx_printf("[%kLo%kck%kpi%kck%k_R%kCM%k v%d.%d.%d%k]\n\n",
        colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFFF00FF, LP_VER_MJ, LP_VER_MN, LP_VER_BF, 0xFFCCCCCC);

    _key_count = 0;
    _titlekey_count = 0;
    color_idx = 0;

    start_time = get_tmr_us();

    _derive_keys();

    emummc_load_cfg();
    // Ignore whether emummc is enabled.
    h_cfg.emummc_force_disable = emu_cfg.sector == 0 && !emu_cfg.path;
    emu_cfg.enabled = !h_cfg.emummc_force_disable;
    if (emmc_storage.initialized) {
        sdmmc_storage_end(&emmc_storage);
    }

    minerva_change_freq(FREQ_800);
    gfx_printf("\n%kPress VOL+ to save a screenshot\n or another button to return to the menu.\n\n", colors[(color_idx++) % 6]);
    u8 btn = btn_wait();
    if (btn == BTN_VOL_UP) {
        int res = save_fb_to_bmp();
        if (!res) {
            gfx_printf("%kScreenshot sd:/switch/lockpick_rcm.bmp saved.", colors[(color_idx++) % 6]);
        } else {
            EPRINTF("Screenshot failed.");
        }
        gfx_printf("\n%kPress a button to return to the menu.", colors[(color_idx++) % 6]);
        btn_wait();
    }
    gfx_clear_grey(0x1B);
}

static void _save_key(const char *name, const void *data, u32 len, char *outbuf) {
    if (!_key_exists(data))
        return;
    u32 pos = strlen(outbuf);
    pos += s_printf(&outbuf[pos], "%s = ", name);
    for (u32 i = 0; i < len; i++)
        pos += s_printf(&outbuf[pos], "%02x", *(u8*)(data + i));
    s_printf(&outbuf[pos], "\n");
    _key_count++;
}

static void _save_key_family(const char *name, const void *data, u32 start_key, u32 num_keys, u32 len, char *outbuf) {
    char *temp_name = calloc(1, 0x40);
    for (u32 i = 0; i < num_keys; i++) {
        s_printf(temp_name, "%s_%02x", name, i + start_key);
        _save_key(temp_name, data + i * len, len, outbuf);
    }
    free(temp_name);
}

// Equivalent to spl::GenerateAesKek
static void _generate_aes_kek(u32 ks, key_derivation_ctx_t *keys, void *out_kek, const void *kek_source, u32 generation, u32 option) {
    bool device_unique = GET_IS_DEVICE_UNIQUE(option);
    u32 seal_key_index = GET_SEAL_KEY_INDEX(option);

    if (generation)
        generation--;

    u8 static_source[AES_128_KEY_SIZE];
    for (u32 i = 0; i < AES_128_KEY_SIZE; i++)
        static_source[i] = aes_kek_generation_source[i] ^ seal_key_masks[seal_key_index][i];

    if (device_unique) {
        _get_device_key(ks, keys, keys->temp_key, generation);
    } else {
        memcpy(keys->temp_key, keys->master_key[generation], sizeof(keys->temp_key));
    }
    se_aes_key_set(ks, keys->temp_key, AES_128_KEY_SIZE);
    se_aes_unwrap_key(ks, ks, static_source);
    se_aes_crypt_block_ecb(ks, DECRYPT, out_kek, kek_source);
}

// Based on spl::LoadAesKey but instead of prepping keyslot, returns calculated key
static void _load_aes_key(u32 ks, void *out_key, const void *access_key, const void *key_source) {
    se_aes_key_set(ks, access_key, AES_128_KEY_SIZE);
    se_aes_crypt_block_ecb(ks, DECRYPT, out_key, key_source);
}

// Equivalent to spl::GenerateAesKey
static void _generate_aes_key(u32 ks, key_derivation_ctx_t *keys, void *out_key, u32 key_size, const void *access_key, const void *key_source) {
    void *aes_key = keys->temp_key;
    _load_aes_key(ks, aes_key, access_key, aes_key_generation_source);
    se_aes_key_set(ks, aes_key, AES_128_KEY_SIZE);
    se_aes_crypt_ecb(ks, DECRYPT, out_key, key_size, key_source, key_size);
}

// Equivalent to smc::PrepareDeviceUniqueDataKey but with no sealing
static void _get_device_unique_data_key(u32 ks, void *out_key, const void *access_key, const void *key_source) {
    _load_aes_key(ks, out_key, access_key, key_source);
}

// Equivalent to spl::DecryptAesKey.
static void _decrypt_aes_key(u32 ks, key_derivation_ctx_t *keys, void *out_key, const void *key_source, u32 generation, u32 option) {
    void *access_key = keys->temp_key;
    _generate_aes_kek(ks, keys, access_key, aes_key_decryption_source, generation, option);
    _generate_aes_key(ks, keys, out_key, AES_128_KEY_SIZE, access_key, key_source);
}

// Equivalent to smc::GetSecureData
static void _get_secure_data(key_derivation_ctx_t *keys, void *out_data) {
    se_aes_key_set(6, keys->device_key, AES_128_KEY_SIZE);
    u8 *d = (u8 *)out_data;
    se_aes_crypt_ctr(6, d + AES_128_KEY_SIZE * 0, AES_128_KEY_SIZE, secure_data_source, AES_128_KEY_SIZE, secure_data_counters[0]);
    se_aes_crypt_ctr(6, d + AES_128_KEY_SIZE * 1, AES_128_KEY_SIZE, secure_data_source, AES_128_KEY_SIZE, secure_data_counters[0]);

    // Apply tweak
    for (u32 i = 0; i < AES_128_KEY_SIZE; i++) {
        d[AES_128_KEY_SIZE + i] ^= secure_data_tweaks[0][i];
    }
}

// Equivalent to spl::GenerateSpecificAesKey
static void _generate_specific_aes_key(u32 ks, key_derivation_ctx_t *keys, void *out_key, const void *key_source, u32 generation) {
    if (fuse_read_bootrom_rev() >= 0x7F) {
        _get_device_key(ks, keys, keys->temp_key, generation - 1);
        se_aes_key_set(ks, keys->temp_key, AES_128_KEY_SIZE);
        se_aes_unwrap_key(ks, ks, retail_specific_aes_key_source); // kek = unwrap(rsaks, devkey)
        se_aes_crypt_ecb(ks, DECRYPT, out_key, AES_128_KEY_SIZE * 2, key_source, AES_128_KEY_SIZE * 2); // bkey = unwrap(bkeys, kek)
    } else {
        _get_secure_data(keys, out_key);
    }
}

static void _get_device_key(u32 ks, key_derivation_ctx_t *keys, void *out_device_key, u32 generation) {
    if (generation == KB_FIRMWARE_VERSION_100 && !h_cfg.t210b01) {
        memcpy(out_device_key, keys->device_key, AES_128_KEY_SIZE);
        return;
    }

    if (generation >= KB_FIRMWARE_VERSION_400) {
        generation -= KB_FIRMWARE_VERSION_400;
    } else {
        generation = 0;
    }
    u32 temp_key_source[AES_128_KEY_SIZE / 4] = {0};
    _load_aes_key(ks, temp_key_source, keys->device_key_4x, device_master_key_source_sources[generation]);
    const void *kek_source = fuse_read_hw_state() == FUSE_NX_HW_STATE_PROD ? device_master_kek_sources[generation] : device_master_kek_sources_dev[generation];
    se_aes_key_set(ks, keys->master_key[0], AES_128_KEY_SIZE);
    se_aes_unwrap_key(ks, ks, kek_source);
    se_aes_crypt_block_ecb(ks, DECRYPT, out_device_key, temp_key_source);
}

// The following ghash implementation is from Atmosphère's original exosphere implementation

/* Shifts right a little endian 128-bit value. */
static void _shr_128(uint64_t *val) {
    val[0] >>= 1;
    val[0] |= (val[1] & 1) << 63;
    val[1] >>= 1;
}

/* Shifts left a little endian 128-bit value. */
static void _shl_128(uint64_t *val) {
    val[1] <<= 1;
    val[1] |= (val[0] & (1ull << 63)) >> 63;
    val[0] <<= 1;
}

/* Multiplies two 128-bit numbers X,Y in the GF(128) Galois Field. */
static void _gf128_mul(uint8_t *dst, const uint8_t *x, const uint8_t *y) {
    uint8_t x_work[0x10];
    uint8_t y_work[0x10];
    uint8_t dst_work[0x10];

    uint64_t *p_x = (uint64_t *)(&x_work[0]);
    uint64_t *p_y = (uint64_t *)(&y_work[0]);
    uint64_t *p_dst = (uint64_t *)(&dst_work[0]);

    /* Initialize buffers. */
    for (unsigned int i = 0; i < 0x10; i++) {
        x_work[i] = x[0xF-i];
        y_work[i] = y[0xF-i];
        dst_work[i] = 0;
    }

    /* Perform operation for each bit in y. */
    for (unsigned int round = 0; round < 0x80; round++) {
        p_dst[0] ^= p_x[0] * ((y_work[0xF] & 0x80) >> 7);
        p_dst[1] ^= p_x[1] * ((y_work[0xF] & 0x80) >> 7);
        _shl_128(p_y);
        uint8_t xval = 0xE1 * (x_work[0] & 1);
        _shr_128(p_x);
        x_work[0xF] ^= xval;
    }

    for (unsigned int i = 0; i < 0x10; i++) {
        dst[i] = dst_work[0xF-i];
    }
}

static void _ghash(u32 ks, void *dst, const void *src, u32 src_size, const void *j_block, bool encrypt) {
    uint8_t x[0x10] = {0};
    uint8_t h[0x10];

    uint64_t *p_x = (uint64_t *)(&x[0]);
    uint64_t *p_data = (uint64_t *)src;

    /* H = aes_ecb_encrypt(zeroes) */
    se_aes_crypt_block_ecb(ks, ENCRYPT, h, x);

    u64 total_size = src_size;

    while (src_size >= 0x10) {
        /* X = (X ^ current_block) * H */
        p_x[0] ^= p_data[0];
        p_x[1] ^= p_data[1];
        _gf128_mul(x, x, h);

        /* Increment p_data by 0x10 bytes. */
        p_data += 2;
        src_size -= 0x10;
    }

    /* Nintendo's code *discards all data in the last block* if unaligned. */
    /* And treats that block as though it were all-zero. */
    /* This is a bug, they just forget to XOR with the copy of the last block they save. */
    if (src_size & 0xF) {
        _gf128_mul(x, x, h);
    }

    uint64_t xor_size = total_size << 3;
    xor_size = __builtin_bswap64(xor_size);

    /* Due to a Nintendo bug, the wrong QWORD gets XOR'd in the "final output block" case. */
    if (encrypt) {
        p_x[0] ^= xor_size;
    } else {
        p_x[1] ^= xor_size;
    }

    _gf128_mul(x, x, h);

    /* If final output block, XOR with encrypted J block. */
    if (encrypt) {
        se_aes_crypt_block_ecb(ks, ENCRYPT, h, j_block);
        for (unsigned int i = 0; i < 0x10; i++) {
            x[i] ^= h[i];
        }
    }
    /* Copy output. */
    memcpy(dst, x, 0x10);
}

static bool _test_key_pair(const void *public_exponent, const void *private_exponent, const void *modulus) {
    u8  plaintext[RSA_2048_KEY_SIZE] __attribute__((aligned(4))) = {0},
        ciphertext[RSA_2048_KEY_SIZE] __attribute__((aligned(4))) = {0},
        work[RSA_2048_KEY_SIZE] __attribute__((aligned(4))) = {0};

    // 0xCAFEBABE
    plaintext[0xfc] = 0xca; plaintext[0xfd] = 0xfe; plaintext[0xfe] = 0xba; plaintext[0xff] = 0xbe;

    se_rsa_key_set(0, modulus, RSA_2048_KEY_SIZE, private_exponent, RSA_2048_KEY_SIZE);
    se_rsa_exp_mod(0, ciphertext, RSA_2048_KEY_SIZE, plaintext, RSA_2048_KEY_SIZE);

    se_rsa_key_set(0, modulus, RSA_2048_KEY_SIZE, public_exponent, 4);
    se_rsa_exp_mod(0, work, RSA_2048_KEY_SIZE, ciphertext, RSA_2048_KEY_SIZE);

    return !memcmp(plaintext, work, RSA_2048_KEY_SIZE);
}
