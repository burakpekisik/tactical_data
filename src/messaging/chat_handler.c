#include "chat_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <jwt.h>
#include "handle_manager.h"
#include "chat_handler.h"
#include "chat_utils.h"
#include "chat_protocol.h"
#include "crypto_utils.h"
#include "logger.h"
#include "database.h"
#include <cjson/cJSON.h>
#include "broadcast_manager.h"

extern server_chat_room_t server_rooms[MAX_CHAT_ROOMS];
extern int server_room_count;

/**
 * @brief Şifreli JSON isteklerini işler ve veritabanına kaydeder
 * @ingroup server
 * 
 * Bu fonksiyon ENCRYPTED protokol komutunu işler. Hex formatındaki
 * şifreli veriyi çözer, JSON'a dönüştürür ve veritabanına kaydeder.
 * 
 * İşlem adımları:
 * 1. Session key geçerliliğini kontrol eder
 * 2. Hex string'i byte array'e çevirir
 * 3. İlk 16 byte'ı IV olarak ayırır
 * 4. AES256 ile veriyi decrypt eder
 * 5. Decrypted JSON'u tactical data'ya parse eder
 * 6. Veritabanına kaydeder ve response üretir
 * 7. Tüm belleği temizler
 * 
 * @param filename İşlem yapılacak dosya adı (log için)
 * @param encrypted_content Hex formatında şifreli veri
 * @param session_key ECDH ile üretilen AES256 session key
 * 
 * @return Başarıda parse sonucu string'i (malloc'lu)
 * @return Hata durumunda hata mesajı (malloc'lu)
 * 
 * @note Döndürülen string caller tarafından free edilmelidir.
 *       Fonksiyon tüm geçici belleği otomatik temizler.
 * 
 * @warning Session key NULL olmamalı, aksi halde hata döner.
 *          Encrypted data en az IV boyutu (16 byte) içermelidir.
 * 
 * Hata durumları:
 * - NULL session key
 * - Geçersiz hex format
 * - Yetersiz veri boyutu (IV eksik)
 * - Decryption başarısızlığı
 * - JSON parse hatası
 * 
 * @see hex_to_bytes()
 * @see decrypt_data()
 * @see parse_json_to_tactical_data()
 * @see db_save_tactical_data_and_get_response()
 */
// Sifreli istek ile bas et
// --- Chat mesaj geçmişi (chat_get_messages) handler ---
char* handle_chat_get_messages(const char* decrypted_json) {
    PRINTF_LOG("[CHAT] handle_chat_get_messages çağrıldı\n");
    PRINTF_LOG("[CHAT] Gelen JSON: %s\n", decrypted_json);
    cJSON* root = cJSON_Parse(decrypted_json);
    if (!root) {
        PRINTF_LOG("[CHAT][ERROR] JSON parse error\n");
        return strdup("{\"error\":\"JSON parse error\"}");
    }
    cJSON* room_id_item = cJSON_GetObjectItem(root, "room_id");
    int room_id = room_id_item && cJSON_IsNumber(room_id_item) ? room_id_item->valueint : -1;
    int limit = 20; // Varsayılan limit
    cJSON* limit_item = cJSON_GetObjectItem(root, "limit");
    if (limit_item && cJSON_IsNumber(limit_item)) limit = limit_item->valueint;
    if (room_id <= 0) {
        cJSON_Delete(root);
        return strdup("{\"error\":\"Geçersiz room_id\"}");
    }
    chat_message_t* messages = NULL;
    int count = 0;
    if (db_chat_get_latest_messages(room_id, &messages, &count, limit) != 0) {
        cJSON_Delete(root);
        return strdup("{\"error\":\"Mesajlar alınamadı\"}");
    }
    cJSON* arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "message_id", messages[i].message_id);
        cJSON_AddStringToObject(obj, "sender_id", messages[i].sender_id);
        cJSON_AddStringToObject(obj, "sender_name", messages[i].sender_name);
        cJSON_AddStringToObject(obj, "message", messages[i].message);
        cJSON_AddNumberToObject(obj, "timestamp", (double)messages[i].timestamp);
        cJSON_AddItemToArray(arr, obj);
    }
    if (messages) db_free_chat_messages(messages, count);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddNumberToObject(resp, "room_id", room_id);
    cJSON_AddItemToObject(resp, "messages", arr);
    char* result = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    cJSON_Delete(root);
    return result;
}

// --- Chat odasından çıkma handler ---
char* handle_chat_leave_room(const char* decrypted_json, int client_socket) {
    cJSON* leave_root = cJSON_Parse(decrypted_json);
    int room_id = -1;
    if (leave_root) {
        cJSON* room_id_item = cJSON_GetObjectItem(leave_root, "room_id");
        if (room_id_item && cJSON_IsNumber(room_id_item)) {
            room_id = room_id_item->valueint;
        }
    }
    if (room_id <= 0) {
        if (leave_root) cJSON_Delete(leave_root);
        return strdup("{\"error\":\"Geçersiz room_id\"}");
    }
    // Katılımcı listesinden socket'i çıkar
    int removed = 0;
    int updated_users = -1;
    extern server_chat_room_t server_rooms[];
    extern int server_room_count;
    for (int i = 0; i < server_room_count; i++) {
        if (server_rooms[i].room_id == room_id) {
            for (int j = 0; j < server_rooms[i].participant_count; j++) {
                if (server_rooms[i].participant_sockets[j] == client_socket) {
                    // Katılımcıyı çıkar
                    for (int k = j; k < server_rooms[i].participant_count - 1; k++) {
                        server_rooms[i].participant_sockets[k] = server_rooms[i].participant_sockets[k+1];
                    }
                    server_rooms[i].participant_count--;
                    removed = 1;
                    break;
                }
            }
            updated_users = server_rooms[i].participant_count;
            break;
        }
    }
    // Database'de de güncelle
    if (updated_users >= 0) {
        db_update_chat_room_users(room_id, updated_users);
    }
    if (leave_root) cJSON_Delete(leave_root);
    // Yanıt hazırla
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", removed ? 1 : 0);
    cJSON_AddNumberToObject(resp, "room_id", room_id);
    if (removed) {
        cJSON_AddStringToObject(resp, "msg", "Odadan başarıyla çıkıldı");
    } else {
        cJSON_AddStringToObject(resp, "msg", "Oda katılımcı listesinde bulunamadı veya zaten çıkılmış");
    }
    char* result = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return result;
}

char* handle_chat_send_message(const char* decrypted_json, const char* jwt_token, int client_socket) {
    // JSON parse
    cJSON* root = cJSON_Parse(decrypted_json);
    if (!root) {
        return strdup("{\"success\":false,\"msg\":\"Geçersiz JSON\"}");
    }
    cJSON* room_id_item = cJSON_GetObjectItem(root, "room_id");
    cJSON* message_item = cJSON_GetObjectItem(root, "message"); // encrypted
    if (!room_id_item || !cJSON_IsNumber(room_id_item) || !message_item || !cJSON_IsString(message_item)) {
        cJSON_Delete(root);
        return strdup("{\"success\":false,\"msg\":\"Eksik parametre\"}");
    }
    int room_id = room_id_item->valueint;
    const char* encrypted_message = message_item->valuestring;

    // JWT'den user_id ve name çek
    char sender_id_str[64] = "";
    char sender_name[128] = "";
    if (jwt_token) {
        jwt_t *jwt_ptr = NULL;
        if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
            const char* sub = jwt_get_grant(jwt_ptr, "sub");
            const char* name = jwt_get_grant(jwt_ptr, "name");
            if (sub) strncpy(sender_id_str, sub, sizeof(sender_id_str)-1);
            if (name) strncpy(sender_name, name, sizeof(sender_name)-1);
            jwt_free(jwt_ptr);
        }
    }

    // Oda anahtarını çek
    chat_room_t room;
    memset(&room, 0, sizeof(room));
    if (db_select_chat_room_by_id(room_id, &room) != 0) {
        cJSON_Delete(root);
        return strdup("{\"success\":false,\"msg\":\"Oda bulunamadı\"}");
    }

    // Mesajı çöz
    char* plain_message = NULL;
    if (decrypt_chat_message(encrypted_message, strlen(encrypted_message), room.room_key, &plain_message) != 0) {
        cJSON_Delete(root);
        return strdup("{\"success\":false,\"msg\":\"Mesaj çözülemedi\"}");
    }

    // Mesajı DB'ye ekle
    int db_result = db_insert_chat_message(room_id, sender_id_str, sender_name, plain_message, encrypted_message);
    cJSON* resp = cJSON_CreateObject();
    if (db_result > 0) {
        // Broadcast işlemi (başarılıysa)
        cJSON* broadcast_msg = cJSON_CreateObject();
        cJSON_AddStringToObject(broadcast_msg, "sender_name", sender_name);
        cJSON_AddStringToObject(broadcast_msg, "message", plain_message ? plain_message : "");
        cJSON_AddNumberToObject(broadcast_msg, "timestamp", (double)time(NULL));
        char* broadcast_json = cJSON_PrintUnformatted(broadcast_msg);
        cJSON_Delete(broadcast_msg);
        if (broadcast_json) {
            char* encrypted_broadcast = encrypt_and_format_response(broadcast_json, room.room_key, "chat_receive_message");
            if (encrypted_broadcast) {
                broadcast_message_to_room(room_id, encrypted_broadcast, client_socket);
                free(encrypted_broadcast);
            }
            free(broadcast_json);
        }
        // Bilgi mesajı (ack) olarak da dön
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddNumberToObject(resp, "message_id", db_result);
        cJSON_AddStringToObject(resp, "msg", "Mesaj başarıyla kaydedildi");
        char* result = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        cJSON_Delete(root);
        if (plain_message) free(plain_message);
        return result;
    } else {
        cJSON_AddBoolToObject(resp, "success", 0);
        cJSON_AddStringToObject(resp, "msg", "Mesaj kaydedilemedi");
        char* result = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        cJSON_Delete(root);
        if (plain_message) free(plain_message);
        return result;
    }
}

// --- Chat odasına katılma handler ---
char* handle_chat_join_room(const char* decrypted_json, const char* jwt_token, int client_socket) {
    PRINTF_LOG("[CHAT] handle_chat_join_room çağrıldı\n");
    PRINTF_LOG("[CHAT] Gelen JSON: %s\n", decrypted_json);
    cJSON* root = cJSON_Parse(decrypted_json);
    if (!root) {
        PRINTF_LOG("[CHAT][ERROR] JSON parse error\n");
        return strdup("{\"error\":\"JSON parse error\"}");
    }
    cJSON* room_id_item = cJSON_GetObjectItem(root, "room_id");
    if (!room_id_item || !cJSON_IsNumber(room_id_item)) {
        cJSON_Delete(root);
        return strdup("{\"error\":\"Eksik veya geçersiz room_id\"}");
    }
    int room_id = room_id_item->valueint;
    // JWT'den user_id al
    char user_id[64] = "";
    if (jwt_token) {
        jwt_t *jwt_ptr = NULL;
        if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
            const char* sub = jwt_get_grant(jwt_ptr, "sub");
            if (sub) strncpy(user_id, sub, sizeof(user_id)-1);
            jwt_free(jwt_ptr);
        }
    }
    if (user_id[0] == '\0') {
        cJSON_Delete(root);
        return strdup("{\"error\":\"JWT geçersiz veya user_id alınamadı\"}");
    }
    // Odayı bul
    chat_room_t room;
    memset(&room, 0, sizeof(room));
    if (db_select_chat_room_by_id(room_id, &room) != 0) {
        cJSON_Delete(root);
        return strdup("{\"error\":\"Oda bulunamadı\"}");
    }
    // Kullanıcı yetkisini JWT'den al
    int user_privilege = USER_PRIVILEGE;
    if (jwt_token) {
        jwt_t *jwt_ptr = NULL;
        if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
            user_privilege = jwt_get_grant_int(jwt_ptr, "privilege");
            jwt_free(jwt_ptr);
        }
    }
    // Odaya erişim yetkisi kontrolü
    if (!chat_db_is_user_allowed_in_room(user_id, user_privilege, &room)) {
        cJSON_Delete(root);
        return strdup("{\"error\":\"Bu odaya katılma yetkiniz yok\"}");
    }
    // Oda doluluk kontrolü
    if (room.current_users >= room.max_users) {
        cJSON_Delete(root);
        return strdup("{\"error\":\"Oda dolu, katılım mümkün değil\"}");
    }
    // --- Katılımcı socket'i odaya ekle ve kullanıcı sayısını güncelle ---
    if (room_id > 0 && client_socket > 0) {
        add_socket_to_room(room_id, client_socket);
        // Hafızadaki oda listesinden güncel kullanıcı sayısını bul ve veritabanını güncelle
        extern server_chat_room_t server_rooms[];
        extern int server_room_count;
        for (int i = 0; i < server_room_count; i++) {
            if (server_rooms[i].room_id == room_id) {
                db_update_chat_room_users(room_id, server_rooms[i].participant_count);
                break;
            }
        }
    }
    // Oda anahtarını hex olarak hazırla
    char room_key_hex[ROOM_KEY_SIZE*2+1];
    for (int i = 0; i < ROOM_KEY_SIZE; i++) {
        sprintf(room_key_hex + i*2, "%02x", room.room_key[i]);
    }
    room_key_hex[ROOM_KEY_SIZE*2] = '\0';
    // Başarılı yanıt
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddNumberToObject(resp, "room_id", room_id);
    cJSON_AddStringToObject(resp, "room_key", room_key_hex);
    cJSON_AddStringToObject(resp, "msg", "Odaya başarıyla katıldınız");
    char* result = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    cJSON_Delete(root);
    return result;
}

char* handle_chat_list_rooms(const char* decrypted_json, const char* jwt_token) {
    PRINTF_LOG("[CHAT] handle_chat_list_rooms çağrıldı\n");
    PRINTF_LOG("[CHAT] Gelen JSON: %s\n", decrypted_json);
    // JWT'den user_id ve privilege al
    char user_id[64] = "";
    int user_privilege = 0;
    if (jwt_token) {
        jwt_t *jwt_ptr = NULL;
        if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
            const char* sub = jwt_get_grant(jwt_ptr, "sub");
            if (sub) strncpy(user_id, sub, sizeof(user_id)-1);
            user_privilege = jwt_get_grant_int(jwt_ptr, "privilege");
            jwt_free(jwt_ptr);
        }
    }
    chat_room_t* rooms = NULL;
    int count = 0;
    db_select_user_accessible_chat_rooms(user_id, user_privilege, &rooms, &count);
    PRINTF_LOG("[CHAT] db_select_user_accessible_chat_rooms: user_id=%s, privilege=%d, count=%d\n", user_id, user_privilege, count);
    cJSON* arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "room_name", rooms[i].room_name);
        cJSON_AddNumberToObject(obj, "room_id", rooms[i].room_id);
        cJSON_AddNumberToObject(obj, "room_type", rooms[i].room_type);
        cJSON_AddNumberToObject(obj, "max_users", rooms[i].max_users);
        cJSON_AddNumberToObject(obj, "current_users", rooms[i].current_users);
        cJSON_AddStringToObject(obj, "creator_id", rooms[i].creator_id);
        cJSON_AddStringToObject(obj, "allowed_user_ids", rooms[i].allowed_user_ids);
        cJSON_AddNumberToObject(obj, "is_active", rooms[i].is_active);
        cJSON_AddItemToArray(arr, obj);
        PRINTF_LOG("[CHAT] Oda: id=%d, name=%s, type=%d, max_users=%d, current_users=%d, creator_id=%s, is_active=%d\n", rooms[i].room_id, rooms[i].room_name, rooms[i].room_type, rooms[i].max_users, rooms[i].current_users, rooms[i].creator_id, rooms[i].is_active);
    }
    if (rooms) db_free_chat_rooms(rooms, count);
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "success");
    cJSON_AddItemToObject(root, "rooms", arr);
    char* result = cJSON_PrintUnformatted(root);
    PRINTF_LOG("[CHAT] JSON yanıt: %s\n", result);
    cJSON_Delete(root);
    return result;
}

// --- CHAT HANDLER FONKSİYONLARI ---
char* handle_chat_create_room(const char* decrypted_json, const char* jwt_token) {
    PRINTF_LOG("[CHAT] handle_chat_create_room çağrıldı\n");
    PRINTF_LOG("[CHAT] Gelen JSON: %s\n", decrypted_json);
    cJSON* root = cJSON_Parse(decrypted_json);
    if (!root) {
        PRINTF_LOG("[CHAT][ERROR] JSON parse error\n");
        return strdup("{\"error\":\"JSON parse error\"}");
    }
    cJSON* room_name = cJSON_GetObjectItem(root, "room_name");
    cJSON* room_type = cJSON_GetObjectItem(root, "room_type");
    cJSON* max_users = cJSON_GetObjectItem(root, "max_users");
    cJSON* allowed_user_ids = cJSON_GetObjectItem(root, "allowed_user_ids");
    if (!room_name || !room_type || !max_users) {
        PRINTF_LOG("[CHAT][ERROR] Eksik parametre\n");
        cJSON_Delete(root);
        return strdup("{\"error\":\"Eksik parametre\"}");
    }
    // JWT'den creator_id al
    char creator_id[64] = "";
    if (jwt_token) {
        jwt_t *jwt_ptr = NULL;
        if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
            const char* sub = jwt_get_grant(jwt_ptr, "sub");
            if (sub) strncpy(creator_id, sub, sizeof(creator_id)-1);
            jwt_free(jwt_ptr);
        }
    }
    chat_room_t room;
    memset(&room, 0, sizeof(room));
    strncpy(room.room_name, room_name->valuestring, sizeof(room.room_name)-1);
    strncpy(room.creator_id, creator_id, sizeof(room.creator_id)-1);
    room.room_type = room_type->valueint;
    room.max_users = max_users->valueint;
    room.current_users = 1;
    if (allowed_user_ids && cJSON_IsString(allowed_user_ids)) {
        strncpy(room.allowed_user_ids, allowed_user_ids->valuestring, sizeof(room.allowed_user_ids)-1);
    } else {
        room.allowed_user_ids[0] = '\0';
    }
    // Oda anahtarı ve diğer alanlar
    for (int i = 0; i < ROOM_KEY_SIZE; i++) room.room_key[i] = rand() % 256;
    room.created_at = time(NULL);
    room.is_active = 1;
    PRINTF_LOG("[CHAT] Oda oluşturuluyor: name=%s, type=%d, max_users=%d, creator_id=%s\n", room.room_name, room.room_type, room.max_users, room.creator_id);
    int insert_result = db_insert_chat_room(&room);
    PRINTF_LOG("[CHAT] db_insert_chat_room sonucu: %d\n", insert_result);
    cJSON_Delete(root);
    if (insert_result > 0) {
        PRINTF_LOG("[CHAT] Oda başarıyla oluşturuldu\n");
        // Oda ID'sini ve anahtarını JSON ile dön
        cJSON* resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddNumberToObject(resp, "room_id", insert_result); // db_insert_chat_room room_id döndürmeli
        // room_key'i hex olarak ekle
        char room_key_hex[ROOM_KEY_SIZE*2+1];
        for (int i = 0; i < ROOM_KEY_SIZE; i++) {
            sprintf(room_key_hex + i*2, "%02x", room.room_key[i]);
        }
        room_key_hex[ROOM_KEY_SIZE*2] = '\0';
        cJSON_AddStringToObject(resp, "room_key", room_key_hex);
        cJSON_AddStringToObject(resp, "msg", "Oda oluşturuldu");
        char* result = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return result;
    } else {
        PRINTF_LOG("[CHAT][ERROR] Oda oluşturulamadı\n");
        return strdup("{\"error\":\"Oda oluşturulamadı\"}");
    }
}