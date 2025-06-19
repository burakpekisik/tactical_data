#ifndef _CRYPTO_UTILS_H_
#define _CRYPTO_UTILS_H_

#include <stdint.h>
#include <stddef.h>
#include "ecdh.h"

// AES256 key ve IV boyutları
#define CRYPTO_KEY_SIZE 32  // AES256 için 32 byte
#define CRYPTO_IV_SIZE 16

// Şifreleme sonuç yapısı
typedef struct {
    uint8_t *data;
    size_t length;
    int success;
} crypto_result_t;

// ECDH anahtar yönetimi yapısı
typedef struct {
    uint8_t private_key[ECC_PRV_KEY_SIZE];
    uint8_t public_key[ECC_PUB_KEY_SIZE];
    uint8_t shared_secret[ECC_PUB_KEY_SIZE];
    uint8_t aes_key[CRYPTO_KEY_SIZE];
    int initialized;
} ecdh_context_t;

// Function prototypes
crypto_result_t* encrypt_data(const char* plaintext, const uint8_t* key, const uint8_t* iv);
char* decrypt_data(const uint8_t* ciphertext, size_t length, const uint8_t* key, const uint8_t* iv);
void free_crypto_result(crypto_result_t* result);
size_t calculate_padded_length(size_t original_length);
void apply_pkcs7_padding(uint8_t* data, size_t original_length, size_t padded_length);
int remove_pkcs7_padding(uint8_t* data, size_t* length);
void generate_random_iv(uint8_t* iv);

// Hex encoding/decoding için
char* bytes_to_hex(const uint8_t* bytes, size_t length);
uint8_t* hex_to_bytes(const char* hex, size_t* out_length);

// ECDH anahtar yönetimi fonksiyonları
int ecdh_init_context(ecdh_context_t* ctx);
int ecdh_generate_keypair(ecdh_context_t* ctx);
int ecdh_compute_shared_secret(ecdh_context_t* ctx, const uint8_t* other_public_key);
int ecdh_derive_aes_key(ecdh_context_t* ctx);
void ecdh_cleanup_context(ecdh_context_t* ctx);

// Güvenli rastgele sayı üretimi
int generate_secure_random(uint8_t* buffer, size_t length);

#endif // _CRYPTO_UTILS_H_
