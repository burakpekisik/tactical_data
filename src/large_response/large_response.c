#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "large_response.h"
#include "logger.h"
#include "config.h"
#include <stdint.h>
#include "crypto_utils.h"


// Büyük plain yanıtlarını parça parça gönder (REPLY_QUERY gibi durumlarda)
void send_large_plain_response(int client_socket, const char* command, const char* data) {
    size_t data_len = strlen(data);
    const size_t PLAIN_PART_SIZE = 8192; // 8KB chunks
    int total_parts = (data_len + PLAIN_PART_SIZE - 1) / PLAIN_PART_SIZE;
    
    PRINTF_LOG("[SERVER][PLAIN_PART] %s yanıtı parça parça gönderiliyor. Toplam uzunluk: %zu, Parça sayısı: %d\n", 
               command, data_len, total_parts);
    
    for (int i = 0; i < total_parts; ++i) {
        size_t start = i * PLAIN_PART_SIZE;
        size_t part_len = (start + PLAIN_PART_SIZE < data_len) ? PLAIN_PART_SIZE : (data_len - start);
        
        char header[128];
        snprintf(header, sizeof(header), "PLAIN_PART:%s:%d:%d:%zu:", command, i+1, total_parts, part_len);
        
        size_t msg_len = strlen(header) + part_len + 2; // +1 for \n, +1 for \0
        char* msg = malloc(msg_len);
        strcpy(msg, header);
        memcpy(msg + strlen(header), data + start, part_len);
        msg[strlen(header) + part_len] = '\n';
        msg[strlen(header) + part_len + 1] = '\0';
        
        PRINTF_LOG("[SERVER][PLAIN_PART] %s parça %d/%d gönderiliyor, uzunluk: %zu\n", 
                   command, i+1, total_parts, part_len);
        
        send(client_socket, msg, strlen(header) + part_len + 1, 0); // +1 for \n
        free(msg);
    }
}

// Büyük ENCRYPTED yanıtlarını parça parça gönder
void send_large_encrypted_response(int client_socket, const char* hex_data) {
    size_t hex_len = strlen(hex_data);
    int total_parts = (hex_len + ENCRYPTED_PART_SIZE - 1) / ENCRYPTED_PART_SIZE;
    PRINTF_LOG("[SERVER][ENCRYPTED_PART] Toplam uzunluk: %zu, Parça sayısı: %d\n", hex_len, total_parts);
    for (int i = 0; i < total_parts; ++i) {
        size_t start = i * ENCRYPTED_PART_SIZE;
        size_t part_len = (start + ENCRYPTED_PART_SIZE < hex_len) ? ENCRYPTED_PART_SIZE : (hex_len - start);
        char header[128];
        snprintf(header, sizeof(header), "ENCRYPTED_PART:%d:%d:%zu:", i+1, total_parts, part_len);
        size_t msg_len = strlen(header) + part_len + 2; // +1 for \n, +1 for \0
        char* msg = malloc(msg_len);
        strcpy(msg, header);
        memcpy(msg + strlen(header), hex_data + start, part_len);
        msg[strlen(header) + part_len] = '\n';
        msg[strlen(header) + part_len + 1] = '\0';
        PRINTF_LOG("[SERVER][ENCRYPTED_PART] Parça %d/%d, Uzunluk: %zu, İlk 32 byte: %.32s\n", i+1, total_parts, part_len, msg + strlen(header));
        send(client_socket, msg, strlen(header) + part_len + 1, 0); // +1 for \n
        free(msg);
    }
}

// Tek parça veya parça parça ENCRYPTED yanıt gönderici
char* send_or_format_large_encrypted_response(int client_socket, const char* plain_result, const uint8_t* session_key, const char* filename) {
    PRINTF_LOG("[SERVER][ENCRYPTED_RESP] send_or_format_large_encrypted_response çağrıldı");
    PRINTF_LOG("[SERVER][ENCRYPTED_RESP] client_socket=%d, filename=%s", client_socket, filename);
    PRINTF_LOG("[SERVER][ENCRYPTED_RESP] plain_result (ilk 256): %.256s", plain_result);
    uint8_t iv[CRYPTO_IV_SIZE];
    generate_random_iv(iv);
    PRINTF_LOG("[SERVER][ENCRYPTED_RESP] IV oluşturuldu");
    crypto_result_t* encrypted = encrypt_data(plain_result, session_key, iv);
    if (!encrypted || !encrypted->success) {
        if (encrypted) free_crypto_result(encrypted);
        char* error_msg = malloc(256);
        strcpy(error_msg, "HATA: Yanıt şifrelenemedi");
        PRINTF_LOG("[SERVER][ENCRYPTED_RESP] Şifreleme başarısız!");
        return error_msg;
    }
    PRINTF_LOG("[SERVER][ENCRYPTED_RESP] Şifreleme başarılı, length=%zu", encrypted->length);
    size_t combined_length = CRYPTO_IV_SIZE + encrypted->length;
    uint8_t* combined_data = malloc(combined_length);
    memcpy(combined_data, iv, CRYPTO_IV_SIZE);
    memcpy(combined_data + CRYPTO_IV_SIZE, encrypted->data, encrypted->length);
    char* hex_data = bytes_to_hex(combined_data, combined_length);
    PRINTF_LOG("[SERVER][ENCRYPTED_RESP] Hex encode tamamlandı, hex_data len=%zu", strlen(hex_data));
    free(combined_data);
    free_crypto_result(encrypted);
    size_t total_size = strlen("ENCRYPTED:") + strlen(filename) + 1 + strlen(hex_data) + 1;
    if (strlen(hex_data) > ENCRYPTED_PART_SIZE) {
        PRINTF_LOG("[SERVER] ENCRYPTED yanıtı uzun, parça parça gönderilecek. Toplam uzunluk: %zu\n", strlen(hex_data));
        if (client_socket >= 0) {
            send_large_encrypted_response(client_socket, hex_data);
        } else {
            PRINTF_LOG("[SERVER] UDP/P2P için ENCRYPTED yanıtı parça parça gönderilmiyor (client_socket yok)\n");
        }
        free(hex_data);
        return NULL;
    } else {
        PRINTF_LOG("[SERVER] ENCRYPTED yanıtı kısa, tek parça gönderilecek. Uzunluk: %zu\n", strlen(hex_data));
        char* result = malloc(total_size);
        snprintf(result, total_size, "ENCRYPTED:%s:%s", filename, hex_data);
        PRINTF_LOG("[SERVER] ENCRYPTED yanıt: %s\n", result);
        if (client_socket >= 0) {
            send(client_socket, result, strlen(result), 0);
            PRINTF_LOG("[SERVER] ENCRYPTED yanıtı tek parça olarak gönderildi (send)\n");
            free(result);
            free(hex_data);
            return NULL;
        } else {
            free(hex_data);
            return result;
        }
    }
}

// Şifreli tek parça veya parça parça gelen ENCRYPTED yanıtları birleştirip çözen fonksiyon
// out_json buffer'ına çözülen JSON yazılır, başarıda 0, hata durumunda -1 döner
// part_callback NULL ise sadece tek parça desteklenir
int receive_and_decrypt_encrypted_response(const char* response, const uint8_t* session_key, char* out_json, size_t out_json_size,
                                           int (*part_callback)(char* buffer, size_t buffer_size)) {
    // response: ENCRYPTED:ACTION:HEXDATA veya ENCRYPTED_PART:... veya birleştirilmiş HEXDATA
    if (strncmp(response, "ENCRYPTED:", 10) == 0) {
        // Tek parça ENCRYPTED yanıt
        const char* p1 = strchr(response + 10, ':');
        if (!p1) return -1;
        const char* hex_data = p1 + 1;
        // HEXDATA'nın başında action olabilir, onu atla
        const char* p2 = strchr(hex_data, ':');
        if (p2) hex_data = p2 + 1;
        // Hex'i byte dizisine çevir
        size_t bin_len = strlen(hex_data) / 2;
        uint8_t* bin_data = malloc(bin_len);
        if (!bin_data) return -1;
        for (size_t i = 0; i < bin_len; ++i) {
            sscanf(hex_data + 2*i, "%2hhx", &bin_data[i]);
        }
        // IV ve ciphertext'i ayır
        if (bin_len < CRYPTO_IV_SIZE) {
            free(bin_data);
            return -1;
        }
        uint8_t iv[CRYPTO_IV_SIZE];
        memcpy(iv, bin_data, CRYPTO_IV_SIZE);
        uint8_t* ciphertext = bin_data + CRYPTO_IV_SIZE;
        size_t ciphertext_len = bin_len - CRYPTO_IV_SIZE;
        // AES ile çöz
        char* decrypted = decrypt_data(ciphertext, ciphertext_len, session_key, iv);
        if (!decrypted) {
            free(bin_data);
            return -1;
        }
        size_t copy_len = strlen(decrypted);
        if (copy_len > out_json_size-1) copy_len = out_json_size-1;
        memcpy(out_json, decrypted, copy_len);
        out_json[copy_len] = '\0';
        free(decrypted);
        free(bin_data);
        return 0;
    } else if (strncmp(response, "ENCRYPTED_PART:", 15) == 0) {
        // Parça parça ENCRYPTED yanıt
        // part_callback ile tüm parçalar birleştirilmeli, burada sadece çözme işlemi yapılır
        if (!part_callback) return -1;
        // part_callback, tüm HEXDATA'yı birleştirip buffer'a yazar ve buffer_size döndürür
        char* hex_buffer = malloc(ENCRYPTED_PART_SIZE * 32); // Yeterli büyük buffer
        int hex_len = part_callback(hex_buffer, ENCRYPTED_PART_SIZE * 32);
        if (hex_len <= 0) {
            free(hex_buffer);
            return -1;
        }
        size_t bin_len = hex_len / 2;
        uint8_t* bin_data = malloc(bin_len);
        if (!bin_data) {
            free(hex_buffer);
            return -1;
        }
        for (size_t i = 0; i < bin_len; ++i) {
            sscanf(hex_buffer + 2*i, "%2hhx", &bin_data[i]);
        }
        if (bin_len < CRYPTO_IV_SIZE) {
            free(bin_data);
            free(hex_buffer);
            return -1;
        }
        uint8_t iv[CRYPTO_IV_SIZE];
        memcpy(iv, bin_data, CRYPTO_IV_SIZE);
        uint8_t* ciphertext = bin_data + CRYPTO_IV_SIZE;
        size_t ciphertext_len = bin_len - CRYPTO_IV_SIZE;
        char* decrypted = decrypt_data(ciphertext, ciphertext_len, session_key, iv);
        if (!decrypted) {
            free(bin_data);
            free(hex_buffer);
            return -1;
        }
        size_t copy_len = strlen(decrypted);
        if (copy_len > out_json_size-1) copy_len = out_json_size-1;
        memcpy(out_json, decrypted, copy_len);
        out_json[copy_len] = '\0';
        free(decrypted);
        free(bin_data);
        free(hex_buffer);
        return 0;
    }
    return -1;
}