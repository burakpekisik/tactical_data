#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "large_response.h"
#include "logger.h"
#include "config.h"


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