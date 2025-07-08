/**
 * @file chat_protocol.c
 * @brief Chat protokol yönetimi ve TCP iletişim fonksiyonları
 * @details Sunucu ile chat mesajlaşması için TCP protokol yönetimi
 * @author Ali Burak Pekışık
 * @date 2025
 */

#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "chat_protocol.h"
#include "chat_utils.h"
#include "crypto_utils.h"
#include "logger.h"
#include <cjson/cJSON.h>
#include "connection_manager.h"

extern char jwt_token[1024];

/**
 * @brief Chat odası oluşturma isteği gönder
 */
int send_create_room_request(client_connection_t* conn, const char* jwt_token, 
                           const char* room_name, chat_room_type_t room_type, 
                           int max_users, const char* allowed_user_ids) {
    LOG_CLIENT_INFO("[DEBUG] send_create_room_request çağrıldı");
    if (!conn || !jwt_token || !room_name) {
        LOG_CLIENT_ERROR("Invalid parameters for create room request");
        return -1;
    }
    // JSON mesaj oluştur
    cJSON* json = cJSON_CreateObject();
    cJSON* json_action = cJSON_CreateString("chat_create_room");
    cJSON* json_token = cJSON_CreateString(jwt_token);
    cJSON* json_room_name = cJSON_CreateString(room_name);
    cJSON* json_room_type = cJSON_CreateNumber(room_type);
    cJSON* json_max_users = cJSON_CreateNumber(max_users);

    cJSON_AddItemToObject(json, "action", json_action);
    cJSON_AddItemToObject(json, "jwt_token", json_token);
    cJSON_AddItemToObject(json, "room_name", json_room_name);
    cJSON_AddItemToObject(json, "room_type", json_room_type);
    cJSON_AddItemToObject(json, "max_users", json_max_users);
    if (allowed_user_ids && strlen(allowed_user_ids) > 0) {
        cJSON* json_allowed_users = cJSON_CreateString(allowed_user_ids);
        cJSON_AddItemToObject(json, "allowed_user_ids", json_allowed_users);
    }
    char* json_string = cJSON_Print(json);
    if (!json_string) {
        LOG_CLIENT_ERROR("Failed to create JSON for room creation");
        cJSON_Delete(json);
        return -1;
    }
    LOG_CLIENT_INFO("Sending create room request: %s", room_name);
    int result = send_encrypted_chat_action(conn, "chat_create_room", json_string, jwt_token);
    free(json_string);
    cJSON_Delete(json);
    return result;
}

/**
 * @brief Oda listesi isteme isteği gönder
 */
int send_list_rooms_request(client_connection_t* conn, const char* jwt_token) {
    LOG_CLIENT_INFO("[DEBUG] send_list_rooms_request çağrıldı");
    if (!conn || !jwt_token) {
        LOG_CLIENT_ERROR("Invalid parameters for list rooms request");
        return -1;
    }
    cJSON* json = cJSON_CreateObject();
    cJSON* json_action = cJSON_CreateString("chat_list_rooms");
    cJSON* json_token = cJSON_CreateString(jwt_token);
    cJSON_AddItemToObject(json, "action", json_action);
    cJSON_AddItemToObject(json, "jwt_token", json_token);
    char* json_string = cJSON_Print(json);
    if (!json_string) {
        LOG_CLIENT_ERROR("Failed to create JSON for room listing");
        cJSON_Delete(json);
        return -1;
    }
    LOG_CLIENT_INFO("Sending list rooms request");
    int result = send_encrypted_chat_action(conn, "chat_list_rooms", json_string, jwt_token);
    free(json_string);
    cJSON_Delete(json);
    return result;
}

/**
 * @brief Sunucudan oda listesini al
 */
chat_room_list_t* receive_room_list(client_connection_t* conn) {
    LOG_CLIENT_INFO("[DEBUG] receive_room_list çağrıldı");
    if (!conn) {
        LOG_CLIENT_ERROR("Invalid connection for receiving room list");
        return NULL;
    }
    char* response = receive_encrypted_response(conn);
    if (!response) {
        LOG_CLIENT_ERROR("Failed to receive room list response");
        return NULL;
    }
    char* decrypted_json = decrypt_protocol_message(response, conn->ecdh_ctx.aes_key);
    free(response);
    if (!decrypted_json) {
        LOG_CLIENT_ERROR("Failed to parse room list JSON. Decrypted response: (null)");
        return NULL;
    }
    cJSON* json = cJSON_Parse(decrypted_json);
    free(decrypted_json);
    if (!json) {
        LOG_CLIENT_ERROR("Failed to parse room list JSON.");
        return NULL;
    }
    cJSON* status_json = cJSON_GetObjectItem(json, "status");
    cJSON* rooms_json = cJSON_GetObjectItem(json, "rooms");
    if (!cJSON_IsString(status_json) || strcmp(status_json->valuestring, "success") != 0 || !cJSON_IsArray(rooms_json)) {
        LOG_CLIENT_ERROR("Room list request failed or invalid rooms array.");
        cJSON_Delete(json);
        return NULL;
    }
    int room_count = cJSON_GetArraySize(rooms_json);
    chat_room_list_t* room_list = malloc(sizeof(chat_room_list_t));
    if (!room_list) {
        LOG_CLIENT_ERROR("Memory allocation failed for room list");
        cJSON_Delete(json);
        return NULL;
    }
    room_list->count = room_count;
    room_list->capacity = room_count;
    room_list->rooms = NULL;
    if (room_count > 0) {
        room_list->rooms = calloc(room_count, sizeof(chat_room_t));
        if (!room_list->rooms) {
            LOG_CLIENT_ERROR("Memory allocation failed for rooms array");
            free(room_list);
            cJSON_Delete(json);
            return NULL;
        }
        for (int i = 0; i < room_count; i++) {
            cJSON* room_json = cJSON_GetArrayItem(rooms_json, i);
            if (!room_json) continue;
            chat_room_t* room = &room_list->rooms[i];
            cJSON* id_json = cJSON_GetObjectItem(room_json, "room_id");
            cJSON* name_json = cJSON_GetObjectItem(room_json, "room_name");
            cJSON* type_json = cJSON_GetObjectItem(room_json, "room_type");
            cJSON* max_users_json = cJSON_GetObjectItem(room_json, "max_users");
            cJSON* current_users_json = cJSON_GetObjectItem(room_json, "current_users");
            if (cJSON_IsNumber(id_json)) room->room_id = id_json->valueint;
            if (cJSON_IsString(name_json)) strncpy(room->room_name, name_json->valuestring, sizeof(room->room_name) - 1);
            if (cJSON_IsNumber(type_json)) room->room_type = (chat_room_type_t)type_json->valueint;
            if (cJSON_IsNumber(max_users_json)) room->max_users = max_users_json->valueint;
            if (cJSON_IsNumber(current_users_json)) room->current_users = current_users_json->valueint;
        }
    }
    cJSON_Delete(json);
    LOG_CLIENT_INFO("Successfully received %d rooms", room_count);
    return room_list;
}

/**
 * @brief Odaya katılma isteği gönder
 */
int send_join_room_request(client_connection_t* conn, const char* jwt_token, int room_id) {
    LOG_CLIENT_INFO("[DEBUG] send_join_room_request çağrıldı");
    if (!conn || !jwt_token || room_id <= 0) {
        LOG_CLIENT_ERROR("Invalid parameters for join room request");
        return -1;
    }
    
    // JSON mesaj oluştur
    cJSON* json = cJSON_CreateObject();
    cJSON* json_action = cJSON_CreateString("chat_join_room");
    cJSON* json_token = cJSON_CreateString(jwt_token);
    cJSON* json_room_id = cJSON_CreateNumber(room_id);
    
    cJSON_AddItemToObject(json, "action", json_action);
    cJSON_AddItemToObject(json, "jwt_token", json_token);
    cJSON_AddItemToObject(json, "room_id", json_room_id);
    
    char* json_string = cJSON_Print(json);
    if (!json_string) {
        LOG_CLIENT_ERROR("Failed to create JSON for room join");
        cJSON_Delete(json);
        return -1;
    }
    
    LOG_CLIENT_INFO("Sending join room request for room %d", room_id);
    
    // Şifreli olarak gönder
    int result = send_encrypted_chat_action(conn, "chat_join_room", json_string, jwt_token);
    
    free(json_string);
    cJSON_Delete(json);
    
    return result;
}

/**
 * @brief Odadan çıkma isteği gönder
 */
int send_leave_room_request(client_connection_t* conn, const char* jwt_token, int room_id) {
    LOG_CLIENT_INFO("[DEBUG] send_leave_room_request çağrıldı");
    if (!conn || !jwt_token || room_id <= 0) {
        LOG_CLIENT_ERROR("Invalid parameters for leave room request");
        return -1;
    }
    
    // JSON mesaj oluştur
    cJSON* json = cJSON_CreateObject();
    cJSON* json_action = cJSON_CreateString("chat_leave_room");
    cJSON* json_token = cJSON_CreateString(jwt_token);
    cJSON* json_room_id = cJSON_CreateNumber(room_id);
    
    cJSON_AddItemToObject(json, "action", json_action);
    cJSON_AddItemToObject(json, "jwt_token", json_token);
    cJSON_AddItemToObject(json, "room_id", json_room_id);
    
    char* json_string = cJSON_Print(json);
    if (!json_string) {
        LOG_CLIENT_ERROR("Failed to create JSON for room leave");
        cJSON_Delete(json);
        return -1;
    }
    
    LOG_CLIENT_INFO("Sending leave room request for room %d", room_id);
    
    // Şifreli olarak gönder (response beklemeden)
    int result = send_encrypted_chat_action(conn, "chat_leave_room", json_string, jwt_token);
    
    free(json_string);
    cJSON_Delete(json);
    
    return result;
}

/**
 * @brief Chat mesajı gönder
 */
int send_chat_message(client_connection_t* conn, const char* jwt_token, 
                     int room_id, const char* message, const uint8_t* room_key) {
    LOG_CLIENT_INFO("[DEBUG] send_chat_message çağrıldı");

    if (!conn || !jwt_token || room_id <= 0 || !message || !room_key) {
        LOG_CLIENT_ERROR("Invalid parameters for sending chat message");
        return -1;
    }
    
    // Mesajı oda anahtarı ile şifrele
    char* encrypted_message = NULL;
    size_t encrypted_len = 0;
    
    if (encrypt_chat_message(message, room_key, &encrypted_message, &encrypted_len) != 0) {
        LOG_CLIENT_ERROR("Failed to encrypt chat message");
        return -1;
    }
    
    // JSON mesaj oluştur
    cJSON* json = cJSON_CreateObject();
    cJSON* json_action = cJSON_CreateString("chat_send_message");
    cJSON* json_token = cJSON_CreateString(jwt_token);
    cJSON* json_room_id = cJSON_CreateNumber(room_id);
    cJSON* json_message = cJSON_CreateString(encrypted_message);
    
    cJSON_AddItemToObject(json, "action", json_action);
    cJSON_AddItemToObject(json, "jwt_token", json_token);
    cJSON_AddItemToObject(json, "room_id", json_room_id);
    cJSON_AddItemToObject(json, "message", json_message);
    
    char* json_string = cJSON_Print(json);
    
    free(encrypted_message);
    
    if (!json_string) {
        LOG_CLIENT_ERROR("Failed to create JSON for chat message");
        cJSON_Delete(json);
        return -1;
    }
    
    LOG_CLIENT_INFO("Sending chat message to room %d", room_id);
    
    // ECDH ile şifreli olarak gönder
    int result = send_encrypted_chat_action(conn, "chat_send_message", json_string, jwt_token);
    
    free(json_string);
    cJSON_Delete(json);
    
    return result;
}

/**
 * @brief Oda anahtarını al
 */
uint8_t* receive_room_key(client_connection_t* conn, const char* jwt_token, int room_id) {
    LOG_CLIENT_INFO("[DEBUG] receive_room_key çağrıldı");

    if (!conn || !jwt_token || room_id <= 0) {
        LOG_CLIENT_ERROR("Invalid parameters for receiving room key");
        return NULL;
    }

    // Odaya katılma isteği gönder ve yanıtı al
    if (send_join_room_request(conn, jwt_token, room_id) != 0) {
        LOG_CLIENT_ERROR("Failed to send join room request");
        return NULL;
    }

    char* response = receive_encrypted_response(conn);
    if (!response) {
        LOG_CLIENT_ERROR("Failed to receive join room response");
        return NULL;
    }

    cJSON* json = cJSON_Parse(response);
    free(response);
    if (!json) {
        LOG_CLIENT_ERROR("Failed to parse join room JSON");
        return NULL;
    }

    cJSON* success_json = cJSON_GetObjectItem(json, "success");
    if (!cJSON_IsBool(success_json) || !cJSON_IsTrue(success_json)) {
        LOG_CLIENT_ERROR("Room join failed");
        cJSON_Delete(json);
        return NULL;
    }

    cJSON* key_json = cJSON_GetObjectItem(json, "room_key");
    if (!cJSON_IsString(key_json)) {
        LOG_CLIENT_ERROR("Invalid room key in join response");
        cJSON_Delete(json);
        return NULL;
    }

    // Hex'den binary'ye çevir
    size_t key_bin_len;
    uint8_t* key_binary = hex_to_bytes(key_json->valuestring, &key_bin_len);
    if (!key_binary || key_bin_len != ROOM_KEY_SIZE) {
        LOG_CLIENT_ERROR("Failed to convert room key from hex");
        if (key_binary) free(key_binary);
        cJSON_Delete(json);
        return NULL;
    }

    uint8_t* room_key = malloc(ROOM_KEY_SIZE);
    if (!room_key) {
        LOG_CLIENT_ERROR("Memory allocation failed for room key");
        free(key_binary);
        cJSON_Delete(json);
        return NULL;
    }
    memcpy(room_key, key_binary, ROOM_KEY_SIZE);
    free(key_binary);
    cJSON_Delete(json);
    LOG_CLIENT_INFO("Successfully received room key for room %d", room_id);
    return room_key;
}

/**
 * @brief Chat mesajını şifrele
 */
int encrypt_chat_message(const char* message, const uint8_t* room_key, 
                        char** encrypted_message, size_t* encrypted_len) {
    LOG_CLIENT_INFO("[DEBUG] encrypt_chat_message çağrıldı");
    
    if (!message || !room_key || !encrypted_message || !encrypted_len) {
        return -1;
    }
    
    // AES ile şifrele
    size_t message_len = strlen(message);
    uint8_t* encrypted_data = encrypt_data_for_chat(message, message_len, room_key, encrypted_len);
    if (!encrypted_data) {
        return -1;
    }
    
    // Hex'e çevir
    *encrypted_message = bytes_to_hex(encrypted_data, *encrypted_len);
    free(encrypted_data);
    
    if (!*encrypted_message) {
        return -1;
    }
    
    return 0;
}

/**
 * @brief Chat mesajını çöz
 */
int decrypt_chat_message(const char* encrypted_message, size_t encrypted_len __attribute__((unused)), 
                        const uint8_t* room_key, char** decrypted_message) {
    LOG_CLIENT_INFO("[DEBUG] decrypt_chat_message çağrıldı");
    // Room key hex dump
    char key_hex[ROOM_KEY_SIZE*2+1];
    for (int i = 0; i < ROOM_KEY_SIZE; i++) {
        sprintf(&key_hex[i*2], "%02x", room_key[i]);
    }
    key_hex[ROOM_KEY_SIZE*2] = '\0';
    LOG_CLIENT_INFO("[DEBUG] Room key (hex): %s", key_hex);
    LOG_CLIENT_INFO("[DEBUG] Room key length: %d", ROOM_KEY_SIZE);

    // Encrypted message ilk 32 karakterini logla
    char msg_preview[33];
    strncpy(msg_preview, encrypted_message, 32);
    msg_preview[32] = '\0';
    LOG_CLIENT_INFO("[DEBUG] Encrypted message (first 32): %s", msg_preview);

    if (!encrypted_message || !room_key || !decrypted_message) {
        return -1;
    }
    
    // Hex'den binary'ye çevir
    size_t binary_len = strlen(encrypted_message) / 2;
    uint8_t* binary_data = malloc(binary_len);
    if (!binary_data) {
        return -1;
    }
    
    size_t actual_len;
    uint8_t* hex_result = hex_to_bytes(encrypted_message, &actual_len);
    if (!hex_result || actual_len != binary_len) {
        free(binary_data);
        if (hex_result) free(hex_result);
        return -1;
    }
    
    memcpy(binary_data, hex_result, binary_len);
    free(hex_result);
    
    // AES ile çöz
    size_t decrypted_len;
    uint8_t* decrypted_data = decrypt_data_for_chat(binary_data, binary_len, room_key, &decrypted_len);
    free(binary_data);
    
    if (!decrypted_data) {
        return -1;
    }
    
    // String olarak döndür
    *decrypted_message = malloc(decrypted_len + 1);
    if (!*decrypted_message) {
        free(decrypted_data);
        return -1;
    }
    
    memcpy(*decrypted_message, decrypted_data, decrypted_len);
    (*decrypted_message)[decrypted_len] = '\0';
    
    free(decrypted_data);
    return 0;
}

/**
 * @brief Oda mesajlarını al ve göster
 */
int receive_chat_messages(client_connection_t* conn, const char* jwt_token, 
                         int room_id, const uint8_t* room_key) {
    LOG_CLIENT_INFO("[DEBUG] receive_chat_messages çağrıldı");
    flush_socket(conn->socket); // Socket'i temizle, önceki mesajları atla

    if (!conn || !jwt_token || room_id <= 0 || !room_key) {
        LOG_CLIENT_ERROR("Invalid parameters for receiving chat messages");
        return -1;
    }
    
    // JSON mesaj oluştur
    cJSON* json = cJSON_CreateObject();
    cJSON* json_action = cJSON_CreateString("chat_get_messages");
    cJSON* json_token = cJSON_CreateString(jwt_token);
    cJSON* json_room_id = cJSON_CreateNumber(room_id);
    cJSON* json_limit = cJSON_CreateNumber(20); // Son 20 mesaj
    
    cJSON_AddItemToObject(json, "action", json_action);
    cJSON_AddItemToObject(json, "jwt_token", json_token);
    cJSON_AddItemToObject(json, "room_id", json_room_id);
    cJSON_AddItemToObject(json, "limit", json_limit);
    
    char* json_string = cJSON_Print(json);
    if (!json_string) {
        LOG_CLIENT_ERROR("Failed to create JSON for get messages");
        cJSON_Delete(json);
        return -1;
    }
    
    LOG_CLIENT_INFO("Requesting messages for room %d", room_id);
    
    // ENCRYPTED protokolü ile gönder
    if (send_encrypted_chat_action(conn, "chat_get_messages", json_string, jwt_token) != 0) {
        free(json_string);
        cJSON_Delete(json);
        return -1;
    }
    free(json_string);
    cJSON_Delete(json);
    
    // Cevabı al
    char* response = receive_encrypted_response(conn);
    if (!response) {
        LOG_CLIENT_ERROR("Failed to receive messages response");
        return -1;
    }
    // ENCRYPTED:action:hexdata[:jwt_token] formatı olabilir, hexdata kısmını ayıkla
    char* decrypted_json = NULL;
    if (strncmp(response, "ENCRYPTED:", 10) == 0) {
        // ENCRYPTED:action:hexdata[:jwt_token] formatı
        const char* p1 = strchr(response + 10, ':');
        if (p1) {
            const char* p2 = strchr(p1 + 1, ':');
            if (p2) {
                // p1+1'den p2'ye kadar hexdata
                size_t hexdata_len = p2 - (p1 + 1);
                char* hexdata = malloc(hexdata_len + 1);
                if (hexdata) {
                    memcpy(hexdata, p1 + 1, hexdata_len);
                    hexdata[hexdata_len] = '\0';
                    // ENCRYPTED:dummy:hexdata formatına çevir
                    size_t newmsg_len = 10 + 12 + 1 + hexdata_len + 1;
                    char* newmsg = malloc(newmsg_len);
                    if (newmsg) {
                        snprintf(newmsg, newmsg_len, "ENCRYPTED:chat_get_messages:%s", hexdata);
                        decrypted_json = decrypt_protocol_message(newmsg, room_key);
                        free(newmsg);
                    }
                    free(hexdata);
                }
            } else {
                // Sadece ENCRYPTED:action:hexdata formatı
                decrypted_json = decrypt_protocol_message(response, room_key);
            }
        } else {
            // ENCRYPTED:hexdata gibi bir format, doğrudan çöz
            decrypted_json = decrypt_protocol_message(response, room_key);
        }
    } else {
        // ENCRYPTED ile başlamıyorsa, doğrudan çöz
        decrypted_json = decrypt_protocol_message(response, room_key);
    }
    // LOG_CLIENT_INFO("[DEBUG] Decrypted chat_get_messages JSON: %s", decrypted_json ? decrypted_json : "(null)");
    // PRINTF_CLIENT("\n[DEBUG] Decrypted chat_get_messages JSON: %s\n", decrypted_json ? decrypted_json : "(null)");
    free(response);
    if (!decrypted_json) {
        LOG_CLIENT_ERROR("Failed to decrypt messages response");
        return -1;
    }
    // JSON parse et
    cJSON* response_json = cJSON_Parse(decrypted_json);
    if (!response_json) {
        LOG_CLIENT_ERROR("Failed to parse messages JSON. Raw: %s", decrypted_json);
        PRINTF_CLIENT("\n[SERVER] %s\n", decrypted_json); // Hata veya bilgi mesajını kullanıcıya göster
        free(decrypted_json);
        return -1;
    }
    free(decrypted_json);
    
    cJSON* messages_json = cJSON_GetObjectItem(response_json, "messages");
    if (!cJSON_IsArray(messages_json)) {
        // Eğer messages array yoksa, bilgi mesajı olarak göster ve çık
        PRINTF_CLIENT("\n[SERVER] %s\n", cJSON_PrintUnformatted(response_json));
        LOG_CLIENT_ERROR("No messages array in response, info message shown to user.");
        cJSON_Delete(response_json);
        return 0;
    }
    
    int message_count = cJSON_GetArraySize(messages_json);
    PRINTF_CLIENT("\n📜 Son %d mesaj:\n", message_count);
    PRINTF_CLIENT("─────────────────────────────────────────────────────\n");
    
    // Mesajları göster
    for (int i = 0; i < message_count; i++) {
        cJSON* msg_json = cJSON_GetArrayItem(messages_json, i);
        if (!msg_json) continue;

        cJSON* sender_name_json = cJSON_GetObjectItem(msg_json, "sender_name");
        cJSON* message_json = cJSON_GetObjectItem(msg_json, "message");
        cJSON* timestamp_json = cJSON_GetObjectItem(msg_json, "timestamp");

        if (!cJSON_IsString(sender_name_json) || !cJSON_IsString(message_json) ||
            !cJSON_IsNumber(timestamp_json)) {
            continue;
        }

        // Önce decrypt etmeyi dene, başarısızsa olduğu gibi kullan
        char* decrypted_message = NULL;
        int decrypt_ok = decrypt_chat_message(message_json->valuestring,
                                             strlen(message_json->valuestring),
                                             room_key, &decrypted_message);
        const char* final_message = NULL;
        if (decrypt_ok == 0 && decrypted_message && strlen(decrypted_message) > 0) {
            final_message = decrypted_message;
        } else {
            final_message = message_json->valuestring;
        }

        char* formatted_msg = format_chat_message_display(
            sender_name_json->valuestring,
            final_message,
            (time_t)timestamp_json->valueint
        );

        if (formatted_msg) {
            PRINTF_CLIENT("%s\n", formatted_msg);
            free(formatted_msg);
        }
        if (decrypted_message) free(decrypted_message);
    }
    
    PRINTF_CLIENT("─────────────────────────────────────────────────────\n");
    
    cJSON_Delete(response_json);
    return 0;
}

/**
 * @brief Şifreli veri gönder ve yanıt bekle
 */
int send_encrypted_data_with_response(client_connection_t* conn, const char* data, size_t data_len __attribute__((unused))) {
    LOG_CLIENT_INFO("[DEBUG] send_encrypted_data_with_response çağrıldı");

    if (!conn || !data) {
        return -1;
    }
    
    // ECDH anahtarını kontrol et
    if (!conn->ecdh_initialized) {
        LOG_CLIENT_ERROR("ECDH not initialized");
        return -1;
    }
    
    // IV oluştur
    uint8_t iv[CRYPTO_IV_SIZE];
    generate_random_iv(iv);
    
    // Şifrele
    crypto_result_t* encrypted = encrypt_data(data, conn->ecdh_ctx.aes_key, iv);
    if (!encrypted || !encrypted->success) {
        LOG_CLIENT_ERROR("Failed to encrypt data");
        if (encrypted) free_crypto_result(encrypted);
        return -1;
    }
    
    // Hex'e çevir
    char* iv_hex = bytes_to_hex(iv, CRYPTO_IV_SIZE);
    char* data_hex = bytes_to_hex(encrypted->data, encrypted->length);
    
    if (!iv_hex || !data_hex) {
        LOG_CLIENT_ERROR("Failed to convert to hex");
        if (iv_hex) free(iv_hex);
        if (data_hex) free(data_hex);
        free_crypto_result(encrypted);
        return -1;
    }
    
    // IV+data formatında mesaj oluştur
    size_t message_len = strlen(iv_hex) + strlen(data_hex) + 1;
    char* message = malloc(message_len);
    if (!message) {
        free(iv_hex);
        free(data_hex);
        free_crypto_result(encrypted);
        return -1;
    }
    
    strcpy(message, iv_hex);
    strcat(message, data_hex);
    
    // Gönder
    ssize_t sent = send(conn->socket, message, strlen(message), 0);
    
    free(iv_hex);
    free(data_hex);
    free(message);
    free_crypto_result(encrypted);
    
    return (sent > 0) ? 0 : -1;
}

/**
 * @brief Şifreli veri gönder (yanıt beklemeden)
 */
int send_encrypted_data(client_connection_t* conn, const char* data, size_t data_len) {
    LOG_CLIENT_INFO("[DEBUG] send_encrypted_data çağrıldı");

    return send_encrypted_data_with_response(conn, data, data_len);
}


/**
 * @brief Şifreli yanıt al (session key ile)
 */
char* receive_encrypted_response(client_connection_t* conn) {
    LOG_CLIENT_INFO("[RECEIVE] receive_encrypted_response çağrıldı");
    if (!conn) {
        return NULL;
    }
    char buffer[65536];
    ssize_t received = recv(conn->socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        LOG_CLIENT_ERROR("[RECEIVE] Failed to receive response");
        return NULL;
    }
    buffer[received] = '\0';
    if (!conn->ecdh_initialized) {
        LOG_CLIENT_ERROR("[RECEIVE] ECDH not initialized for decryption");
        return NULL;
    }
    return decrypt_protocol_message(buffer, conn->ecdh_ctx.aes_key);
}

/**
 * @brief Şifreli yanıt al (oda anahtarı ile)
 */
char* receive_encrypted_response_room_key(client_connection_t* conn, const uint8_t* room_key) {
    LOG_CLIENT_INFO("[RECEIVE] receive_encrypted_response_room_key çağrıldı");
    if (!conn || !room_key) {
        return NULL;
    }
    char buffer[65536];
    ssize_t received = recv(conn->socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        LOG_CLIENT_ERROR("[RECEIVE] Failed to receive response");
        return NULL;
    }
    buffer[received] = '\0';
    // Oda anahtarı ile çöz
    return decrypt_protocol_message(buffer, room_key);
}

/**
 * @brief Şifreli chat eylemi gönder
 */
int send_encrypted_chat_action(client_connection_t* conn, const char* action_name, const char* json_string, const char* jwt_token) {
    flush_socket(conn->socket); // Socket'i temizle, önceki mesajları atla
    
    LOG_CLIENT_INFO("[DEBUG] send_encrypted_chat_action çağrıldı");
    
    if (!conn || !action_name || !json_string || !jwt_token) {
        LOG_CLIENT_ERROR("Invalid parameters for send_encrypted_chat_action");
        return -1;
    }
    if (!conn->ecdh_initialized) {
        LOG_CLIENT_ERROR("ECDH not initialized");
        return -1;
    }
    // IV oluştur
    uint8_t iv[CRYPTO_IV_SIZE];
    generate_random_iv(iv);
    // Şifrele
    crypto_result_t* encrypted = encrypt_data(json_string, conn->ecdh_ctx.aes_key, iv);
    if (!encrypted || !encrypted->success) {
        LOG_CLIENT_ERROR("Failed to encrypt chat action");
        if (encrypted) free_crypto_result(encrypted);
        return -1;
    }
    // IV+data hexle
    size_t total_len = CRYPTO_IV_SIZE + encrypted->length;
    uint8_t* combined = malloc(total_len);
    memcpy(combined, iv, CRYPTO_IV_SIZE);
    memcpy(combined + CRYPTO_IV_SIZE, encrypted->data, encrypted->length);
    char* hexdata = bytes_to_hex(combined, total_len);
    free(combined);
    free_crypto_result(encrypted);
    if (!hexdata) {
        LOG_CLIENT_ERROR("Failed to hex encode chat action");
        return -1;
    }
    // ENCRYPTED:action:hexdata:jwt_token
    size_t msglen = strlen("ENCRYPTED:") + strlen(action_name) + 1 + strlen(hexdata) + 1 + strlen(jwt_token) + 1;
    char* protocol_msg = malloc(msglen);
    snprintf(protocol_msg, msglen, "ENCRYPTED:%s:%s:%s", action_name, hexdata, jwt_token);
    printf("[DEBUG] Protocol message: %s\n", protocol_msg); // Debug log
    free(hexdata);
    ssize_t sent = send(conn->socket, protocol_msg, strlen(protocol_msg), 0);
    free(protocol_msg);
    return (sent > 0) ? 0 : -1;
}

/**
 * @brief Sokette bekleyen tüm verileri temizler (discard)
 */
void flush_socket(int sockfd) {
    int bytes_available = 0;
    // Sokette veri var mı kontrol et
    while (ioctl(sockfd, FIONREAD, &bytes_available) == 0 && bytes_available > 0) {
        char discard_buf[4096];
        ssize_t n = recv(sockfd, discard_buf, sizeof(discard_buf), MSG_DONTWAIT);
        if (n <= 0) break; // Hata veya veri yok
    }
}
