#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "crypto_utils.h"
#include "config.h"
#include "encrypted_client.h"
#include "fallback_manager.h"
#include "protocol_manager.h"

// Normal protokol mesajini olustur: "PARSE:FILENAME:CONTENT"
char* create_normal_protocol_message(const char* filename, const char* content) {
    size_t total_size = strlen("PARSE:") + strlen(filename) + strlen(content) + 2;
    char *message = malloc(total_size);
    
    if (message == NULL) {
        printf("Bellek tahsis hatasi\n");
        return NULL;
    }
    
    snprintf(message, total_size, "PARSE:%s:%s", filename, content);
    return message;
}

// Sifreli protokol mesajini olustur: "ENCRYPTED:FILENAME:HEX_DATA"
char* create_encrypted_protocol_message(const char* filename, const char* content, const uint8_t* session_key) {
    if (session_key == NULL) {
        printf("Session key NULL - şifreleme yapılamaz\n");
        return NULL;
    }
    
    // Random IV olustur
    uint8_t iv[CRYPTO_IV_SIZE];
    generate_random_iv(iv);
    
    printf("Random IV olusturuldu\n");
    
    // JSON'u sifrele
    crypto_result_t* encrypted = encrypt_data(content, session_key, iv);
    if (encrypted == NULL || !encrypted->success) {
        printf("Sifreleme hatasi\n");
        if (encrypted) free_crypto_result(encrypted);
        return NULL;
    }
    
    printf("JSON basariyla sifrelendi (%zu byte)\n", encrypted->length);
    
    // IV + sifreli veri kombinasyonu olustur
    size_t combined_length = CRYPTO_IV_SIZE + encrypted->length;
    uint8_t* combined_data = malloc(combined_length);
    if (combined_data == NULL) {
        printf("Bellek tahsis hatasi\n");
        free_crypto_result(encrypted);
        return NULL;
    }
    
    memcpy(combined_data, iv, CRYPTO_IV_SIZE);
    memcpy(combined_data + CRYPTO_IV_SIZE, encrypted->data, encrypted->length);
    
    // Hex string'e cevir
    char* hex_data = bytes_to_hex(combined_data, combined_length);
    free(combined_data);
    free_crypto_result(encrypted);
    
    if (hex_data == NULL) {
        printf("Hex donusumu hatasi\n");
        return NULL;
    }
    
    printf("Hex encoding tamamlandi (%zu karakter)\n", strlen(hex_data));
    
    // Protokol mesajini olustur
    size_t total_size = strlen("ENCRYPTED:") + strlen(filename) + strlen(hex_data) + 3;
    char *message = malloc(total_size);
    
    if (message == NULL) {
        printf("Bellek tahsis hatasi\n");
        free(hex_data);
        return NULL;
    }
    
    snprintf(message, total_size, "ENCRYPTED:%s:%s", filename, hex_data);
    free(hex_data);
    
    return message;
}

// Baglantiyi kapat
void close_connection(client_connection_t* conn) {
    if (conn != NULL) {
        if (conn->ecdh_initialized) {
            ecdh_cleanup_context(&conn->ecdh_ctx);
        }
        if (conn->socket >= 0) {
            close(conn->socket);
        }
        free(conn);
    }
}

// TCP mesaj gonder
int send_tcp_message(client_connection_t* conn, const char* message) {
    ssize_t bytes_sent = send(conn->socket, message, strlen(message), 0);
    if (bytes_sent < 0) {
        perror("TCP send hatasi");
        return -1;
    }
    printf("TCP mesaj gonderildi (%zd bytes)\n", bytes_sent);
    
    // Yanıt bekle
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("TCP yanit alindi (%zd bytes)\n", bytes_received);
        printf("\nServer yaniti:\n");
        printf("=============\n");
        printf("%s\n", buffer);
        printf("=============\n");
        return 0;
    } else if (bytes_received == 0) {
        printf("TCP baglanti kapatildi\n");
        return -1;
    } else {
        printf("TCP yanitlama hatasi\n");
        return -1;
    }
}

// UDP mesaj gonder
int send_udp_message(client_connection_t* conn, const char* message) {
    ssize_t bytes_sent = sendto(conn->socket, message, strlen(message), 0,
                               (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr));
    if (bytes_sent < 0) {
        perror("UDP send hatasi");
        return -1;
    }
    printf("UDP mesaj gonderildi (%zd bytes)\n", bytes_sent);
    
    // Yanıt bekle
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_udp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("UDP yanit alindi (%zd bytes)\n", bytes_received);
        printf("\nServer yaniti:\n");
        printf("=============\n");
        printf("%s\n", buffer);
        printf("=============\n");
        return 0;
    } else if (bytes_received == 0) {
        printf("UDP baglanti kapatildi\n");
        return -1;
    } else {
        printf("UDP yanitlama hatasi\n");
        return -1;
    }
}

// P2P mesaj gonder
int send_p2p_message(client_connection_t* conn, const char* message) {
    char p2p_message[CONFIG_BUFFER_SIZE];
    
    // Mesaj zaten P2P formatında mı kontrol et
    if (strncmp(message, "P2P_", 4) == 0) {
        // Mesaj zaten P2P formatında - direkt gönder
        strncpy(p2p_message, message, sizeof(p2p_message) - 1);
        p2p_message[sizeof(p2p_message) - 1] = '\0';
        printf("P2P formatlanmış mesaj gönderiliyor...\n");
    } else if (strncmp(message, "ENCRYPTED:", 10) == 0) {
        // Şifreli veri için P2P_ENCRYPTED formatında gönder
        snprintf(p2p_message, sizeof(p2p_message), "P2P_ENCRYPTED:%s", message);
        printf("P2P şifreli mesaj gönderiliyor...\n");
    } else {
        // Normal veri için P2P_DATA formatında gönder
        snprintf(p2p_message, sizeof(p2p_message), "P2P_DATA:CLIENT_%d:%s", 
                 getpid(), message);
        printf("P2P normal mesaj gönderiliyor...\n");
    }
    
    ssize_t bytes_sent = send(conn->socket, p2p_message, strlen(p2p_message), 0);
    if (bytes_sent < 0) {
        perror("P2P send hatasi");
        return -1;
    }
    printf("P2P mesaj gonderildi (%zd bytes)\n", bytes_sent);
    
    // Yanıt bekle
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_p2p_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("P2P yanit alindi (%zd bytes)\n", bytes_received);
        printf("\nServer yaniti:\n");
        printf("=============\n");
        printf("%s\n", buffer);
        printf("=============\n");
        return 0;
    } else if (bytes_received == 0) {
        printf("P2P baglanti kapatildi\n");
        return -1;
    } else {
        printf("P2P yanitlama hatasi\n");
        return -1;
    }
}

// TCP yanit al
int receive_tcp_response(client_connection_t* conn, char* buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(conn->socket, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        perror("TCP receive hatasi");
        return -1;
    } else if (bytes_received == 0) {
        printf("TCP baglanti kapatildi\n");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    printf("TCP yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}

// UDP yanit al
int receive_udp_response(client_connection_t* conn, char* buffer, size_t buffer_size) {
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t bytes_received = recvfrom(conn->socket, buffer, buffer_size - 1, 0,
                                     (struct sockaddr*)&from_addr, &from_len);
    if (bytes_received < 0) {
        perror("UDP receive hatasi");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    printf("UDP yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}

// P2P yanit al
int receive_p2p_response(client_connection_t* conn, char* buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(conn->socket, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        perror("P2P receive hatasi");
        return -1;
    } else if (bytes_received == 0) {
        printf("P2P baglanti kapatildi\n");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    printf("P2P yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}
