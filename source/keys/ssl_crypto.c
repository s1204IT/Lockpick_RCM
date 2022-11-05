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

#include "ssl_crypto.h"

#include "../config.h"

extern hekate_config h_cfg;

void ssl_derive_rsa_kek_device_unique(key_storage_t *keys, void *out_rsa_kek, u32 generation) {
    if ((!h_cfg.t210b01 && !key_exists(keys->device_key)) || (h_cfg.t210b01 && (!key_exists(keys->master_key[0]) || !key_exists(keys->device_key_4x)))) {
        return;
    }

    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_SSL_KEY) | IS_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, ssl_client_cert_kek_source, ssl_client_cert_key_source, generation, option);
}

void ssl_derive_rsa_kek_legacy(key_storage_t *keys, void *out_rsa_kek) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    const u32 generation = 0;
    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_DECRYPT_DEVICE_UNIQUE_DATA) | NOT_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, ssl_rsa_kekek_source, ssl_rsa_kek_source_legacy, generation, option);
}

void ssl_derive_rsa_kek_original(key_storage_t *keys, void *out_rsa_kek, bool is_dev) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    const void *ssl_kek_source = is_dev ? ssl_rsa_kek_source_dev : ssl_rsa_kek_source;
    const u32 generation = 0;
    u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_DECRYPT_DEVICE_UNIQUE_DATA) | NOT_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, ssl_rsa_kekek_source, ssl_kek_source, generation, option);
}
