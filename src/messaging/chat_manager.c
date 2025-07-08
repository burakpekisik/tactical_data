/**
 * @file chat_manager.c
 * @brief Ana chat yönetim fonksiyonları
 * @details Chat odası oluşturma, listeleme ve mesajlaşma oturumu yönetimi
 * @author Ali Burak Pekışık
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "chat_manager.h"
#include "chat_protocol.h"
#include "chat_utils.h"
#include "cjson/cJSON.h"
#include "jwt_manager.h"
#include "logger.h"
#include "config.h"
#include "database.h"
#include "chat_listener.h"

/**
 * @brief Interaktif chat odası oluşturma
 */
int create_chat_room_interactive(client_connection_t* conn, const char* jwt_token) {
    LOG_CLIENT_INFO("[DEBUG] create_chat_room_interactive çağrıldı");

    if (!conn || !jwt_token) {
        LOG_CLIENT_ERROR("Invalid parameters for room creation");
        return -1;
    }
    
    char room_name[MAX_ROOM_NAME_LEN];
    chat_room_type_t room_type;
    int max_users;
    char* allowed_user_ids = NULL;
    
    // Kullanıcı privilege'ini kontrol et
    int user_privilege = get_jwt_privilege(jwt_token);
    if (user_privilege < 0) {
        PRINTF_CLIENT("JWT doğrulanamadı!\n");
        return -1;
    }
    
    PRINTF_CLIENT("\n=== YENİ CHAT ODASI OLUŞTUR ===\n");
    
    // Oda adını al
    PRINTF_CLIENT("Oda adını girin (max %d karakter): ", MAX_ROOM_NAME_LEN-1);
    if (fgets(room_name, sizeof(room_name), stdin) == NULL) {
        PRINTF_CLIENT("Oda adı alınamadı!\n");
        return -1;
    }
    room_name[strcspn(room_name, "\n")] = 0; // Newline kaldır
    
    if (!validate_room_name(room_name)) {
        PRINTF_CLIENT("Geçersiz oda adı!\n");
        return -1;
    }
    
    // Oda tipini al
    room_type = get_room_type_from_user();
    if (room_type < 0) {
        return -1;
    }
    
    // Maksimum kullanıcı sayısını al
    max_users = get_max_users_from_user();
    if (max_users <= 0) {
        return -1;
    }
    
    // Eğer belirli kullanıcılar seçildiyse, user ID listesini al
    if (room_type == ROOM_TYPE_SPECIFIC_USERS) {
        allowed_user_ids = get_user_ids_from_user();
        if (!allowed_user_ids) {
            return -1;
        }
    }
    
    // Sunucuya oda oluşturma isteği gönder
    LOG_CLIENT_INFO("Sending room creation request: %s", room_name);
    int result = send_create_room_request(conn, jwt_token, room_name, room_type, 
                                        max_users, allowed_user_ids);

    if (result != 0) {
        PRINTF_CLIENT("❌ Oda oluşturma isteği gönderilemedi!\n");
        LOG_CLIENT_ERROR("Failed to send create room request: %s", room_name);
        if (allowed_user_ids) {
            free(allowed_user_ids);
        }
        return -1;
    }

    if (allowed_user_ids) {
        free(allowed_user_ids);
    }

    // Oda oluşturma yanıtını al ve kontrol et
    char* create_room_response = receive_encrypted_response(conn);
    int create_success = 0;
    int created_room_id = -1;
    uint8_t created_room_key[ROOM_KEY_SIZE];
    memset(created_room_key, 0, sizeof(created_room_key));
    if (create_room_response) {
        cJSON* json = cJSON_Parse(create_room_response);
        if (json) {
            cJSON* success = cJSON_GetObjectItem(json, "success");
            cJSON* room_id = cJSON_GetObjectItem(json, "room_id");
            cJSON* room_key = cJSON_GetObjectItem(json, "room_key");
            if (cJSON_IsBool(success) && cJSON_IsTrue(success) && cJSON_IsNumber(room_id) && cJSON_IsString(room_key)) {
                create_success = 1;
                created_room_id = room_id->valueint;
                // room_key hex -> binary
                const char* key_hex = room_key->valuestring;
                size_t hexlen = strlen(key_hex);
                for (size_t i = 0; i < ROOM_KEY_SIZE && i*2+1 < hexlen; i++) {
                    unsigned int byte;
                    sscanf(key_hex + i*2, "%2x", &byte);
                    created_room_key[i] = (uint8_t)byte;
                }
                PRINTF_CLIENT("✅ Chat odası başarıyla oluşturuldu: %s (ID: %d)\n", room_name, created_room_id);
                LOG_CLIENT_INFO("Room created successfully: %s (ID: %d)", room_name, created_room_id);
            } else {
                PRINTF_CLIENT("❌ Chat odası oluşturulamadı!\n");
                LOG_CLIENT_ERROR("Failed to create room: %s", room_name);
            }
            cJSON_Delete(json);
        } else {
            PRINTF_CLIENT("❌ Chat odası oluşturulamadı!\n");
            LOG_CLIENT_ERROR("Failed to parse create room response: %s", create_room_response);
        }
        free(create_room_response);
    } else {
        PRINTF_CLIENT("❌ Chat odası oluşturulamadı!\n");
        LOG_CLIENT_ERROR("Failed to receive create room response: %s", room_name);
    }

    if (create_success && created_room_id > 0) {
        PRINTF_CLIENT("🚪 Oluşturduğunuz odaya otomatik katılım yapılıyor...\n");
        usleep(100000); // 100ms
        int join_result = join_chat_room_direct(conn, jwt_token, created_room_id, created_room_key);
        if (join_result == 0) {
            PRINTF_CLIENT("🎉 Başarıyla odaya katıldınız!\n");
        } else {
            PRINTF_CLIENT("❌ Odaya katılım başarısız! (join_chat_room_direct hata)\n");
            LOG_CLIENT_ERROR("Failed to join room: id=%d (join_chat_room_direct)", created_room_id);
            PRINTF_CLIENT("Ana menüye dönülüyor.\n");
        }
    }
    return create_success ? 0 : -1;
}

/**
 * @brief Chat odalarını listele ve katıl
 */
int list_and_join_chat_rooms(client_connection_t* conn, const char* jwt_token) {
    LOG_CLIENT_INFO("[DEBUG] list_and_join_chat_rooms çağrıldı");

    if (!conn || !jwt_token) {
        LOG_CLIENT_ERROR("Invalid parameters for room listing");
        return -1;
    }
    
    // Kullanıcı privilege'ini kontrol et
    int user_privilege = get_jwt_privilege(jwt_token);
    if (user_privilege < 0) {
        PRINTF_CLIENT("JWT doğrulanamadı!\n");
        return -1;
    }
    
    PRINTF_CLIENT("\n=== MEVCUT CHAT ODALARI ===\n");
    
    // Sunucudan oda listesini al
    if (send_list_rooms_request(conn, jwt_token) != 0) {
        PRINTF_CLIENT("❌ Oda listesi alınamadı!\n");
        return -1;
    }
    
    chat_room_list_t* room_list = receive_room_list(conn);
    if (!room_list || room_list->count == 0) {
        PRINTF_CLIENT("📭 Henüz hiç chat odası yok.\n");
        if (room_list) chat_room_list_free(room_list);
        return 0;
    }
    
    // Odaları listele
    PRINTF_CLIENT("\nKatılabileceğiniz odalar:\n");
    PRINTF_CLIENT("─────────────────────────────────────────────────────\n");
    
    for (int i = 0; i < room_list->count; i++) {
        PRINTF_CLIENT("%d. ", i + 1);
        print_room_info(&room_list->rooms[i]);
    }
    
    PRINTF_CLIENT("─────────────────────────────────────────────────────\n");
    PRINTF_CLIENT("Katılmak istediğiniz odanın numarasını girin (0: çık): ");
    
    int choice;
    if (scanf("%d", &choice) != 1) {
        PRINTF_CLIENT("Geçersiz seçim!\n");
        while (getchar() != '\n'); // Buffer temizle
        chat_room_list_free(room_list);
        return -1;
    }
    while (getchar() != '\n'); // Buffer temizle
    
    if (choice == 0) {
        PRINTF_CLIENT("Çıkılıyor...\n");
        chat_room_list_free(room_list);
        return 0;
    }
    
    if (choice < 1 || choice > room_list->count) {
        PRINTF_CLIENT("❌ Geçersiz oda numarası!\n");
        chat_room_list_free(room_list);
        return -1;
    }
    
    int selected_room_id = room_list->rooms[choice - 1].room_id;
    char selected_room_name[MAX_ROOM_NAME_LEN];
    strncpy(selected_room_name, room_list->rooms[choice - 1].room_name, sizeof(selected_room_name) - 1);
    selected_room_name[sizeof(selected_room_name) - 1] = '\0';
    
    chat_room_list_free(room_list);
    
    // Seçilen odaya katıl
    PRINTF_CLIENT("🚪 '%s' odasına katılıyor...\n", selected_room_name);
    return enter_chat_session(conn, jwt_token, selected_room_id);
}

/**
 * @brief Chat oturumu başlat (WhatsApp tarzı)
 */
int enter_chat_session(client_connection_t* conn, const char* jwt_token, int room_id) {
    LOG_CLIENT_INFO("[DEBUG] enter_chat_session çağrıldı");

    if (!conn || !jwt_token || room_id <= 0) {
        LOG_CLIENT_ERROR("Invalid parameters for chat session");
        return -1;
    }
    
    // Odaya katılma isteği gönder
    if (send_join_room_request(conn, jwt_token, room_id) != 0) {
        PRINTF_CLIENT("❌ Odaya katılamadı!\n");
        return -1;
    }
    
    // Oda anahtarını al
    uint8_t* room_key = receive_room_key(conn, jwt_token, room_id);
    if (!room_key) {
        PRINTF_CLIENT("❌ Oda şifreleme anahtarı alınamadı!\n");
        return -1;
    }
    
    PRINTF_CLIENT("✅ Odaya başarıyla katıldınız!\n");
    PRINTF_CLIENT("💬 Mesajlaşmaya başlayabilirsiniz. Çıkmak için '/quit' yazın.\n");
    PRINTF_CLIENT("📜 Son mesajları görmek için '/history' yazın.\n");
    PRINTF_CLIENT("═══════════════════════════════════════════════════════════\n");
    
    // Son mesajları göster
    // receive_chat_messages(conn, jwt_token, room_id, room_key);
    
    // --- Real-time mesaj dinleyici thread başlat ---
    chat_listener_args_t* listener_args = malloc(sizeof(chat_listener_args_t));
    listener_args->conn = conn;
    memcpy(listener_args->room_key, room_key, ROOM_KEY_SIZE);
    listener_args->running = 1;
    pthread_mutex_init(&listener_args->lock, NULL);
    pthread_t listener_tid;
    pthread_create(&listener_tid, NULL, chat_listener_thread, listener_args);

    char message[MAX_MESSAGE_LEN];
    while (1) {
        PRINTF_CLIENT("\n> ");
        fflush(stdout);
        if (fgets(message, sizeof(message), stdin) == NULL) {
            break;
        }
        message[strcspn(message, "\n")] = 0;
        if (strlen(message) == 0) continue;
        if (strcmp(message, "/quit") == 0) {
            PRINTF_CLIENT("🚪 Odadan çıkılıyor...\n");
            break;
        }
        if (strcmp(message, "/history") == 0) {
            PRINTF_CLIENT("📜 Son mesajları getiriliyor...\n");
            receive_chat_messages(conn, jwt_token, room_id, room_key);
            continue;
        }
        if (!is_valid_message(message)) {
            PRINTF_CLIENT("❌ Geçersiz mesaj!\n");
            continue;
        }
        if (send_chat_message(conn, jwt_token, room_id, message, room_key) != 0) {
            PRINTF_CLIENT("❌ Mesaj gönderilemedi!\n");
        }
    }

    // PRINTF_CLIENT("[LEAVE] Oda ID: %d, Oda Anahtarı: %s\n", room_id, bytes_to_hex(room_key, ROOM_KEY_SIZE));
    // Odadan çık
    send_leave_room_request(conn, jwt_token, room_id);
    if (room_key) {
        free(room_key);
    }
    PRINTF_CLIENT("✅ Chat oturumu sonlandırıldı.\n");

    // Thread'i durdur
    pthread_mutex_lock(&listener_args->lock);
    listener_args->running = 0;
    pthread_mutex_unlock(&listener_args->lock);
    pthread_join(listener_tid, NULL);
    pthread_mutex_destroy(&listener_args->lock);
    free(listener_args);
   
    return 0;
}

/**
 * @brief Belirli bir chat odasına doğrudan katıl
 * @details Oda ID'si ve anahtarı ile doğrudan odaya katılım sağlar
 * @param conn Bağlantı yapısı
 * @param jwt_token JWT token
 * @param room_id Katılınacak oda ID'si  
 * @param room_key Oda anahtarı
 * @return int İşlem sonucu (0=başarılı, -1=hata)
 */
int join_chat_room_direct(client_connection_t* conn, const char* jwt_token, 
                         int room_id, const uint8_t* room_key) {
    LOG_CLIENT_INFO("[DEBUG] join_chat_room_direct çağrıldı");

    if (!conn || !jwt_token || !room_key) {
        LOG_CLIENT_ERROR("Invalid parameters for direct room join");
        return -1;
    }
    
    // Odaya katılma isteği gönder
    if (send_join_room_request(conn, jwt_token, room_id) != 0) {
        LOG_CLIENT_ERROR("Failed to send join room request");
        return -1;
    }

    // Chat session'ı başlatırken room_key parametresi varsa tekrar anahtar isteme
    return enter_chat_session_with_key(conn, jwt_token, room_id, room_key);
}

/**
 * @brief Kullanıcıdan oda tipini al
 */
int get_room_type_from_user(void) {
    LOG_CLIENT_INFO("[DEBUG] get_room_type_from_user çağrıldı");
    
    PRINTF_CLIENT("\nOda erişim tipini seçin:\n");
    PRINTF_CLIENT("1. Herkes katılabilir\n");
    PRINTF_CLIENT("2. Sadece adminler katılabilir\n");
    PRINTF_CLIENT("3. Belirli kullanıcılar katılabilir\n");
    PRINTF_CLIENT("Seçiminiz (1-3): ");
    
    int choice;
    if (scanf("%d", &choice) != 1) {
        PRINTF_CLIENT("Geçersiz seçim!\n");
        while (getchar() != '\n');
        return -1;
    }
    while (getchar() != '\n');
    
    switch (choice) {
        case 1: return ROOM_TYPE_EVERYONE;
        case 2: return ROOM_TYPE_ADMIN_ONLY;
        case 3: return ROOM_TYPE_SPECIFIC_USERS;
        default:
            PRINTF_CLIENT("❌ Geçersiz seçim!\n");
            return -1;
    }
}

/**
 * @brief Kullanıcıdan maksimum kullanıcı sayısını al
 */
int get_max_users_from_user(void) {
    LOG_CLIENT_INFO("[DEBUG] get_max_users_from_user çağrıldı");

    PRINTF_CLIENT("Maksimum kullanıcı sayısını girin (1-%d): ", MAX_ROOM_USERS);
    
    int max_users;
    if (scanf("%d", &max_users) != 1) {
        PRINTF_CLIENT("Geçersiz sayı!\n");
        while (getchar() != '\n');
        return -1;
    }
    while (getchar() != '\n');
    
    if (max_users < 1 || max_users > MAX_ROOM_USERS) {
        PRINTF_CLIENT("❌ Kullanıcı sayısı 1-%d arasında olmalı!\n", MAX_ROOM_USERS);
        return -1;
    }
    
    return max_users;
}

/**
 * @brief Kullanıcıdan user ID listesini al
 */
char* get_user_ids_from_user(void) {
    LOG_CLIENT_INFO("[DEBUG] get_user_ids_from_user çağrıldı");

    char input[MAX_USER_ID_LIST];
    PRINTF_CLIENT("İzin verilen kullanıcı ID'lerini virgülle ayırarak girin (örn: 123,456,789): ");
    
    if (fgets(input, sizeof(input), stdin) == NULL) {
        PRINTF_CLIENT("Kullanıcı ID'leri alınamadı!\n");
        return NULL;
    }
    
    input[strcspn(input, "\n")] = 0; // Newline kaldır
    
    if (!validate_user_id_list(input)) {
        PRINTF_CLIENT("❌ Geçersiz kullanıcı ID formatı!\n");
        return NULL;
    }
    
    char* result = malloc(strlen(input) + 1);
    if (!result) {
        PRINTF_CLIENT("❌ Bellek hatası!\n");
        return NULL;
    }
    
    strcpy(result, input);
    return result;
}

/**
 * @brief Oda bilgilerini yazdır
 */
void print_room_info(const chat_room_t* room) {
    LOG_CLIENT_INFO("[DEBUG] print_room_info çağrıldı");
    
    if (!room) return;
    
    const char* type_str;
    switch (room->room_type) {
        case ROOM_TYPE_EVERYONE: type_str = "Herkes"; break;
        case ROOM_TYPE_ADMIN_ONLY: type_str = "Sadece Adminler"; break;
        case ROOM_TYPE_SPECIFIC_USERS: type_str = "Belirli Kullanıcılar"; break;
        default: type_str = "❓ Bilinmeyen"; break;
    }
    
    PRINTF_CLIENT("📋 %s | %s | %d/%d kişi | ID: %d\n", 
                  room->room_name, type_str, room->current_users, room->max_users, room->room_id);
}

/**
 * @brief Chat session başlatıcı: room_key NULL değilse direkt kullan, yoksa eski fonksiyonu çağır
 */
int enter_chat_session_with_key(client_connection_t* conn, const char* jwt_token, int room_id, const uint8_t* room_key) {
    LOG_CLIENT_INFO("[DEBUG] enter_chat_session_with_key çağrıldı");

    if (!conn || !jwt_token || room_id <= 0) {
        LOG_CLIENT_ERROR("Invalid parameters for chat session");
        return -1;
    }

    // Oda anahtarı zaten varsa, direkt kullan
    PRINTF_CLIENT("✅ Odaya başarıyla katıldınız!\n");
    PRINTF_CLIENT("💬 Mesajlaşmaya başlayabilirsiniz. Çıkmak için '/quit' yazın.\n");
    PRINTF_CLIENT("📜 Son mesajları görmek için '/history' yazın.\n");
    PRINTF_CLIENT("═══════════════════════════════════════════════════════════\n");
    
    // --- Real-time mesaj dinleyici thread başlat ---
    chat_listener_args_t* listener_args = malloc(sizeof(chat_listener_args_t));
    listener_args->conn = conn;
    memcpy(listener_args->room_key, room_key, ROOM_KEY_SIZE);
    listener_args->running = 1;
    pthread_mutex_init(&listener_args->lock, NULL);
    pthread_t listener_tid;
    pthread_create(&listener_tid, NULL, chat_listener_thread, listener_args);

    char message[MAX_MESSAGE_LEN];
    while (1) {
        PRINTF_CLIENT("\n> ");
        fflush(stdout);
        if (fgets(message, sizeof(message), stdin) == NULL) {
            break;
        }
        message[strcspn(message, "\n")] = 0;
        if (strlen(message) == 0) {
            continue;
        }
        if (strcmp(message, "/quit") == 0) {
            PRINTF_CLIENT("🚪 Odadan çıkılıyor...\n");
            break;
        }
        if (strcmp(message, "/history") == 0) {
            PRINTF_CLIENT("📜 Son mesajları getiriliyor...\n");
            receive_chat_messages(conn, jwt_token, room_id, room_key);
            continue;
        }
        send_chat_message(conn, jwt_token, room_id, message, room_key);
    }

    // PRINTF_CLIENT("[LEAVE] Oda ID: %d, Oda Anahtarı: %s\n", room_id, bytes_to_hex(room_key, ROOM_KEY_SIZE));
    // Odadan çık
    send_leave_room_request(conn, jwt_token, room_id);
    if (room_key) {
        free(room_key);
    }
    PRINTF_CLIENT("✅ Chat oturumu sonlandırıldı.\n");

    // Thread'i durdur
    pthread_mutex_lock(&listener_args->lock);
    listener_args->running = 0;
    pthread_mutex_unlock(&listener_args->lock);
    pthread_join(listener_tid, NULL);
    pthread_mutex_destroy(&listener_args->lock);
    free(listener_args);
    return 0;
}
