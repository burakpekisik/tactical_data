#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto_utils.h"
#include "config.h"
#include "aes.h"

// Veriyi şifrele
crypto_result_t* encrypt_data(const char* plaintext, const uint8_t* key, const uint8_t* iv) {
    crypto_result_t* result = malloc(sizeof(crypto_result_t));
    if (result == NULL) {
        return NULL;
    }
    
    result->data = NULL;
    result->length = 0;
    result->success = 0;
    
    size_t input_length = strlen(plaintext);
    size_t padded_length = calculate_padded_length(input_length);
    
    // Padded data için bellek tahsis et
    uint8_t* padded_data = malloc(padded_length);
    if (padded_data == NULL) {
        free(result);
        return NULL;
    }
    
    // Veriyi kopyala ve padding uygula
    memcpy(padded_data, plaintext, input_length);
    apply_pkcs7_padding(padded_data, input_length, padded_length);
    
    // AES context oluştur
    struct AES_ctx ctx;
    if (key == NULL) {
        key = CONFIG_DEFAULT_KEY;
    }
    
    AES_init_ctx_iv(&ctx, key, iv);
    
    // CBC modunda şifrele
    AES_CBC_encrypt_buffer(&ctx, padded_data, padded_length);
    
    result->data = padded_data;
    result->length = padded_length;
    result->success = 1;
    
    return result;
}

// Veriyi decrypt et
char* decrypt_data(const uint8_t* ciphertext, size_t length, const uint8_t* key, const uint8_t* iv) {
    if (ciphertext == NULL || length == 0 || length % AES_BLOCKLEN != 0) {
        return NULL;
    }
    
    // Decrypt için buffer oluştur
    uint8_t* decrypted_data = malloc(length);
    if (decrypted_data == NULL) {
        return NULL;
    }
    
    memcpy(decrypted_data, ciphertext, length);
    
    // AES context oluştur
    struct AES_ctx ctx;
    if (key == NULL) {
        key = CONFIG_DEFAULT_KEY;
    }
    
    AES_init_ctx_iv(&ctx, key, iv);
    
    // CBC modunda decrypt et
    AES_CBC_decrypt_buffer(&ctx, decrypted_data, length);
    
    // Padding'i kaldır
    size_t decrypted_length = length;
    if (remove_pkcs7_padding(decrypted_data, &decrypted_length) != 0) {
        free(decrypted_data);
        return NULL;
    }
    
    // Null-terminated string yap
    char* result = malloc(decrypted_length + 1);
    if (result == NULL) {
        free(decrypted_data);
        return NULL;
    }
    
    memcpy(result, decrypted_data, decrypted_length);
    result[decrypted_length] = '\0';
    
    free(decrypted_data);
    return result;
}

// Crypto result belleğini temizle
void free_crypto_result(crypto_result_t* result) {
    if (result != NULL) {
        if (result->data != NULL) {
            free(result->data);
        }
        free(result);
    }
}

// PKCS7 padding için gerekli boyutu hesapla
size_t calculate_padded_length(size_t original_length) {
    size_t padding_needed = AES_BLOCKLEN - (original_length % AES_BLOCKLEN);
    return original_length + padding_needed;
}

// PKCS7 padding uygula
void apply_pkcs7_padding(uint8_t* data, size_t original_length, size_t padded_length) {
    size_t padding_bytes = padded_length - original_length;
    
    for (size_t i = original_length; i < padded_length; i++) {
        data[i] = (uint8_t)padding_bytes;
    }
}

// PKCS7 padding'i kaldır
int remove_pkcs7_padding(uint8_t* data, size_t* length) {
    if (*length == 0) {
        return -1;
    }
    
    uint8_t padding_value = data[*length - 1];
    
    if (padding_value == 0 || padding_value > AES_BLOCKLEN) {
        return -1;
    }
    
    // Padding değerlerini kontrol et
    for (size_t i = *length - padding_value; i < *length; i++) {
        if (data[i] != padding_value) {
            return -1;
        }
    }
    
    *length -= padding_value;
    return 0;
}

// Random IV oluştur
void generate_random_iv(uint8_t* iv) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    
    for (int i = 0; i < CRYPTO_IV_SIZE; i++) {
        iv[i] = (uint8_t)(rand() % 256);
    }
}

// Bytes'ı hex string'e çevir
char* bytes_to_hex(const uint8_t* bytes, size_t length) {
    char* hex_string = malloc(length * 2 + 1);
    if (hex_string == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; i < length; i++) {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]);
    }
    
    hex_string[length * 2] = '\0';
    return hex_string;
}

// Hex string'i bytes'a çevir
uint8_t* hex_to_bytes(const char* hex, size_t* out_length) {
    size_t hex_length = strlen(hex);
    if (hex_length % 2 != 0) {
        return NULL;
    }
    
    *out_length = hex_length / 2;
    uint8_t* bytes = malloc(*out_length);
    if (bytes == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; i < *out_length; i++) {
        int high = 0, low = 0;
        
        // High nibble
        char c = hex[i * 2];
        if (c >= '0' && c <= '9') high = c - '0';
        else if (c >= 'a' && c <= 'f') high = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') high = c - 'A' + 10;
        else {
            free(bytes);
            return NULL;
        }
        
        // Low nibble
        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') low = c - '0';
        else if (c >= 'a' && c <= 'f') low = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') low = c - 'A' + 10;
        else {
            free(bytes);
            return NULL;
        }
        
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    
    return bytes;
}
