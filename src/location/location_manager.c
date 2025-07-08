#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "database.h"
#include "connection_manager.h"
#include <jwt.h>
#include "protocol_manager.h"
#include "logger.h"
#include "location_manager.h"
#include "large_response.h"

// 1. Konum ekle
void send_insert_location(client_connection_t* conn, const location_t* location, const char* jwt_token) {
    jwt_t *jwt;
    int decode_result = jwt_decode(&jwt, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    LOG_SERVER_INFO("[SEND_INSERT_LOCATION] jwt_decode result: %d", decode_result);

    char cmd_json[1024];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"latitude\":%.8f,\"longitude\":%.8f,\"timestamp\":%ld,\"jwt\":\"%s\"}",
        location->latitude, location->longitude, location->timestamp, jwt_token);

    char* protocol_message = create_encrypted_protocol_message("INSERT_LOCATION", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }

    send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);

    // Sunucu yanıtını al ve çöz
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        PRINTF_CLIENT("Sunucudan yanıt alınamadı veya bağlantı kapatıldı.\n");
        return;
    }
    buffer[bytes_received] = '\0';
    PRINTF_CLIENT("[DEBUG] Sunucu yanıtı: %s\n", buffer);

    char json_out[2048];
    int result = receive_and_decrypt_encrypted_response(buffer, conn->ecdh_ctx.aes_key, json_out, sizeof(json_out), NULL);
    if (result == 0) {
        PRINTF_CLIENT("[DEBUG] Çözülen JSON: %s\n", json_out);
    } else {
        PRINTF_CLIENT("Yanıt çözme hatası!\n");
    }
}

// 2. Kullanıcının son konumu
void send_select_location_of_user(client_connection_t* conn, const char* jwt_token) {
    char cmd_json[512];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"jwt\":\"%s\"}", jwt_token);

    char* protocol_message = create_encrypted_protocol_message("SELECT_LOCATION_OF_USER", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }

    send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);

    // Sunucu yanıtını al ve çöz
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        PRINTF_CLIENT("Sunucudan yanıt alınamadı veya bağlantı kapatıldı.\n");
        return;
    }
    buffer[bytes_received] = '\0';
    PRINTF_CLIENT("[DEBUG] Sunucu yanıtı: %s\n", buffer);

    char json_out[2048];
    int result = receive_and_decrypt_encrypted_response(buffer, conn->ecdh_ctx.aes_key, json_out, sizeof(json_out), NULL);
    if (result == 0) {
        PRINTF_CLIENT("[DEBUG] Çözülen JSON: %s\n", json_out);
    } else {
        PRINTF_CLIENT("Yanıt çözme hatası!\n");
    }
}

// 3. Bir unit'teki kullanıcıların son konumları
void send_select_latest_locations_by_unit(client_connection_t* conn, int unit_id, const char* jwt_token) {
    char cmd_json[512];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"unit_id\":%d,\"jwt\":\"%s\"}", unit_id, jwt_token);

    char* protocol_message = create_encrypted_protocol_message("SELECT_LATEST_LOCATIONS_BY_UNIT", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }

    send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);

    // Sunucu yanıtını al ve çöz
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        PRINTF_CLIENT("Sunucudan yanıt alınamadı veya bağlantı kapatıldı.\n");
        return;
    }
    buffer[bytes_received] = '\0';
    PRINTF_CLIENT("[DEBUG] Sunucu yanıtı: %s\n", buffer);

    char json_out[2048];
    int result = receive_and_decrypt_encrypted_response(buffer, conn->ecdh_ctx.aes_key, json_out, sizeof(json_out), NULL);
    if (result == 0) {
        PRINTF_CLIENT("[DEBUG] Çözülen JSON: %s\n", json_out);
    } else {
        PRINTF_CLIENT("Yanıt çözme hatası!\n");
    }
}

// 4. Tüm kullanıcıların son konumları
void send_select_latest_locations_all_users(client_connection_t* conn, const char* jwt_token) {
    char cmd_json[512];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"jwt\":\"%s\"}", jwt_token);

    char* protocol_message = create_encrypted_protocol_message("SELECT_LATEST_LOCATIONS_ALL_USERS", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }

    send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);

    // Sunucu yanıtını al ve çöz
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        PRINTF_CLIENT("Sunucudan yanıt alınamadı veya bağlantı kapatıldı.\n");
        return;
    }
    buffer[bytes_received] = '\0';
    PRINTF_CLIENT("[DEBUG] Sunucu yanıtı: %s\n", buffer);

    char json_out[2048];
    int result = receive_and_decrypt_encrypted_response(buffer, conn->ecdh_ctx.aes_key, json_out, sizeof(json_out), NULL);
    if (result == 0) {
        PRINTF_CLIENT("[DEBUG] Çözülen JSON: %s\n", json_out);
    } else {
        PRINTF_CLIENT("Yanıt çözme hatası!\n");
    }
}

// 5. Çap ile filtrelenmiş son konumlar
void send_select_latest_locations_all_users_by_radius(client_connection_t* conn, double latitude, double longitude, double radius, const char* jwt_token) {
    char cmd_json[512];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"latitude\":%.8f,\"longitude\":%.8f,\"radius\":%.8f,\"jwt\":\"%s\"}",
        latitude, longitude, radius, jwt_token);

    char* protocol_message = create_encrypted_protocol_message("SELECT_LATEST_LOCATIONS_ALL_USERS_BY_RADIUS", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }

    send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);

    // Sunucu yanıtını al ve çöz
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        PRINTF_CLIENT("Sunucudan yanıt alınamadı veya bağlantı kapatıldı.\n");
        return;
    }
    buffer[bytes_received] = '\0';
    PRINTF_CLIENT("[DEBUG] Sunucu yanıtı: %s\n", buffer);

    char json_out[2048];
    int result = receive_and_decrypt_encrypted_response(buffer, conn->ecdh_ctx.aes_key, json_out, sizeof(json_out), NULL);
    if (result == 0) {
        PRINTF_CLIENT("[DEBUG] Çözülen JSON: %s\n", json_out);
    } else {
        PRINTF_CLIENT("Yanıt çözme hatası!\n");
    }
}