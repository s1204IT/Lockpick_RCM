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

#include "crypto.h"

#include "../config.h"
#include "../hos/hos.h"
#include <sec/se.h>
#include <sec/se_t210.h>
#include <soc/fuse.h>
#include <utils/util.h>

#include <string.h>

extern hekate_config h_cfg;

bool test_rsa_keypair(const void *public_exponent, const void *private_exponent, const void *modulus) {
    u32 plaintext[SE_RSA2048_DIGEST_SIZE / 4] = {0},
        ciphertext[SE_RSA2048_DIGEST_SIZE / 4] = {0},
        work[SE_RSA2048_DIGEST_SIZE / 4] = {0};

    plaintext[63] = 0xCAFEBABE;

    se_rsa_key_set(0, modulus, SE_RSA2048_DIGEST_SIZE, private_exponent, SE_RSA2048_DIGEST_SIZE);
    se_rsa_exp_mod(0, ciphertext, SE_RSA2048_DIGEST_SIZE, plaintext, SE_RSA2048_DIGEST_SIZE);

    se_rsa_key_set(0, modulus, SE_RSA2048_DIGEST_SIZE, public_exponent, 4);
    se_rsa_exp_mod(0, work, SE_RSA2048_DIGEST_SIZE, ciphertext, SE_RSA2048_DIGEST_SIZE);

    return memcmp(plaintext, work, SE_RSA2048_DIGEST_SIZE) == 0;
}

bool test_eticket_rsa_keypair(const rsa_keypair_t *keypair) {
    // Unlike the SSL RSA key, we don't need to check the gmac - we can just verify the public exponent
    // and test the keypair since we have the modulus
    if ((read_be_u32(keypair->public_exponent, 0) != RSA_PUBLIC_EXPONENT) ||
        (!test_rsa_keypair(keypair->public_exponent, keypair->private_exponent, keypair->modulus))) {
        return false;
    }
    return true;
}

// Equivalent to spl::GenerateAesKek
void generate_aes_kek(u32 ks, key_storage_t *keys, void *out_kek, const void *kek_source, u32 generation, u32 option) {
    bool device_unique = GET_IS_DEVICE_UNIQUE(option);
    u32 seal_key_index = GET_SEAL_KEY_INDEX(option);

    if (generation)
        generation--;

    u8 static_source[SE_KEY_128_SIZE] __attribute__((aligned(4)));
    for (u32 i = 0; i < SE_KEY_128_SIZE; i++)
        static_source[i] = aes_kek_generation_source[i] ^ seal_key_masks[seal_key_index][i];

    if (device_unique) {
        get_device_key(ks, keys, keys->temp_key, generation);
    } else {
        memcpy(keys->temp_key, keys->master_key[generation], sizeof(keys->temp_key));
    }
    se_aes_key_set(ks, keys->temp_key, SE_KEY_128_SIZE);
    se_aes_unwrap_key(ks, ks, static_source);
    se_aes_crypt_block_ecb(ks, DECRYPT, out_kek, kek_source);
}

// Based on spl::LoadAesKey but instead of prepping keyslot, returns calculated key
void load_aes_key(u32 ks, void *out_key, const void *access_key, const void *key_source) {
    se_aes_key_set(ks, access_key, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(ks, DECRYPT, out_key, key_source);
}

// Equivalent to spl::GenerateAesKey
void generate_aes_key(u32 ks, key_storage_t *keys, void *out_key, u32 key_size, const void *access_key, const void *key_source) {
    void *aes_key = keys->temp_key;
    load_aes_key(ks, aes_key, access_key, aes_key_generation_source);
    se_aes_key_set(ks, aes_key, SE_KEY_128_SIZE);
    se_aes_crypt_ecb(ks, DECRYPT, out_key, key_size, key_source, key_size);
}

// Equivalent to smc::PrepareDeviceUniqueDataKey but with no sealing
void get_device_unique_data_key(u32 ks, void *out_key, const void *access_key, const void *key_source) {
    load_aes_key(ks, out_key, access_key, key_source);
}

// Equivalent to spl::DecryptAesKey.
void decrypt_aes_key(u32 ks, key_storage_t *keys, void *out_key, const void *key_source, u32 generation, u32 option) {
    void *access_key = keys->temp_key;
    generate_aes_kek(ks, keys, access_key, aes_key_decryption_source, generation, option);
    generate_aes_key(ks, keys, out_key, SE_KEY_128_SIZE, access_key, key_source);
}

// Equivalent to smc::GetSecureData
void get_secure_data(key_storage_t *keys, void *out_data) {
    se_aes_key_set(KS_AES_CTR, keys->device_key, SE_KEY_128_SIZE);
    u8 *d = (u8 *)out_data;
    se_aes_crypt_ctr(KS_AES_CTR, d + SE_KEY_128_SIZE * 0, SE_KEY_128_SIZE, secure_data_source, SE_KEY_128_SIZE, secure_data_counters[0]);
    se_aes_crypt_ctr(KS_AES_CTR, d + SE_KEY_128_SIZE * 1, SE_KEY_128_SIZE, secure_data_source, SE_KEY_128_SIZE, secure_data_counters[0]);

    // Apply tweak
    for (u32 i = 0; i < SE_KEY_128_SIZE; i++) {
        d[SE_KEY_128_SIZE + i] ^= secure_data_tweaks[0][i];
    }
}

// Equivalent to spl::GenerateSpecificAesKey
void generate_specific_aes_key(u32 ks, key_storage_t *keys, void *out_key, const void *key_source, u32 generation) {
    if (fuse_read_bootrom_rev() >= 0x7F) {
        get_device_key(ks, keys, keys->temp_key, generation == 0 ? 0 : generation - 1);
        se_aes_key_set(ks, keys->temp_key, SE_KEY_128_SIZE);
        se_aes_unwrap_key(ks, ks, retail_specific_aes_key_source);
        se_aes_crypt_ecb(ks, DECRYPT, out_key, SE_KEY_128_SIZE * 2, key_source, SE_KEY_128_SIZE * 2);
    } else {
        get_secure_data(keys, out_key);
    }
}

void get_device_key(u32 ks, key_storage_t *keys, void *out_device_key, u32 generation) {
    if (generation == KB_FIRMWARE_VERSION_100 && !h_cfg.t210b01) {
        memcpy(out_device_key, keys->device_key, SE_KEY_128_SIZE);
        return;
    }

    if (generation >= KB_FIRMWARE_VERSION_400) {
        generation -= KB_FIRMWARE_VERSION_400;
    } else {
        generation = 0;
    }
    u32 temp_key_source[SE_KEY_128_SIZE / 4] = {0};
    load_aes_key(ks, temp_key_source, keys->device_key_4x, device_master_key_source_sources[generation]);
    const void *kek_source = fuse_read_hw_state() == FUSE_NX_HW_STATE_PROD ? device_master_kek_sources[generation] : device_master_kek_sources_dev[generation];
    se_aes_key_set(ks, keys->master_key[0], SE_KEY_128_SIZE);
    se_aes_unwrap_key(ks, ks, kek_source);
    se_aes_crypt_block_ecb(ks, DECRYPT, out_device_key, temp_key_source);
}
