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

#include "es_crypto.h"

#include "../config.h"

extern hekate_config h_cfg;

bool test_eticket_rsa_keypair(const eticket_rsa_keypair_t *keypair) {
    if (byte_swap_32(keypair->public_exponent) != RSA_PUBLIC_EXPONENT)
        return false;
    return test_rsa_keypair(&keypair->public_exponent, keypair->private_exponent, keypair->modulus);
}

void es_derive_rsa_kek_device_unique(key_storage_t *keys, void *out_rsa_kek, u32 generation, bool is_dev) {
    if ((!h_cfg.t210b01 && !key_exists(keys->device_key)) || (h_cfg.t210b01 && (!key_exists(keys->master_key[0]) || !key_exists(keys->device_key_4x)))) {
        return;
    }

    const void *kek_source = is_dev ? eticket_rsa_kek_source_dev : eticket_rsa_kek_source;
    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY) | IS_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, eticket_rsa_kekek_source, kek_source, generation, option);
}

void es_derive_rsa_kek_legacy(key_storage_t *keys, void *out_rsa_kek) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    const u32 generation = 0;
    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY) | NOT_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, eticket_rsa_kekek_source, eticket_rsa_kek_source_legacy, generation, option);
}

void es_derive_rsa_kek_original(key_storage_t *keys, void *out_rsa_kek, bool is_dev) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    const void *kek_source = is_dev ? eticket_rsa_kek_source_dev : eticket_rsa_kek_source;
    const u32 generation = 0;
    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY) | NOT_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, eticket_rsa_kekek_source, kek_source, generation, option);
}
