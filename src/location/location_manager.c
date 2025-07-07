#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "database.h"
#include "connection_manager.h"

// 1. Konum ekle
void send_insert_location(client_connection_t* conn, const location_t* location, const char* jwt_token) {
    char cmd_json[256];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"user_id\":%d,\"latitude\":%.8f,\"longitude\":%.8f,\"timestamp\":%ld,\"jwt\":\"%s\"}",
        location->user_id, location->latitude, location->longitude, location->timestamp, jwt_token);

    char* protocol_message = create_encrypted_protocol_message("INSERT_LOCATION", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }
    send_tcp_message(conn, protocol_message);
    free(protocol_message);
}

// 2. Kullanıcının son konumu
void send_select_location_of_user(client_connection_t* conn, int user_id, const char* jwt_token) {
    char cmd_json[128];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"user_id\":%d,\"jwt\":\"%s\"}", user_id, jwt_token);

    char* protocol_message = create_encrypted_protocol_message("SELECT_LOCATION_OF_USER", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }
    send_tcp_message(conn, protocol_message);
    free(protocol_message);
}

// 3. Bir unit'teki kullanıcıların son konumları
void send_select_latest_locations_by_unit(client_connection_t* conn, int unit_id, const char* jwt_token) {
    char cmd_json[128];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"unit_id\":%d,\"jwt\":\"%s\"}", unit_id, jwt_token);

    char* protocol_message = create_encrypted_protocol_message("SELECT_LATEST_LOCATIONS_BY_UNIT", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }
    send_tcp_message(conn, protocol_message);
    free(protocol_message);
}

// 4. Tüm kullanıcıların son konumları
void send_select_latest_locations_all_users(client_connection_t* conn, const char* jwt_token) {
    char cmd_json[128];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"jwt\":\"%s\"}", jwt_token);

    char* protocol_message = create_encrypted_protocol_message("SELECT_LATEST_LOCATIONS_ALL_USERS", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }
    send_tcp_message(conn, protocol_message);
    free(protocol_message);
}

// 5. Çap ile filtrelenmiş son konumlar
void send_select_latest_locations_all_users_by_radius(client_connection_t* conn, double latitude, double longitude, double radius, const char* jwt_token) {
    char cmd_json[256];
    snprintf(cmd_json, sizeof(cmd_json),
        "{\"latitude\":%.8f,\"longitude\":%.8f,\"radius\":%.8f,\"jwt\":\"%s\"}",
        latitude, longitude, radius, jwt_token);

    char* protocol_message = create_encrypted_protocol_message("SELECT_LATEST_LOCATIONS_ALL_USERS_BY_RADIUS", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }
    send_tcp_message(conn, protocol_message);
    free(protocol_message);
}