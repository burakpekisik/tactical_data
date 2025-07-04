/**
 * @file chat_utils.c
 * @brief Chat sistemi yardımcı fonksiyonları
 * @details Şifreleme, doğrulama ve formatlama fonksiyonları
 * @author Ali Burak Pekışık
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include "chat_utils.h"
#include "chat_manager.h"
#include "logger.h"

/**
 * @brief Timestamp'i okunabilir formata çevir
 */
char* format_timestamp(time_t timestamp) {
    static char buffer[32];
    struct tm* tm_info = localtime(&timestamp);
    strftime(buffer, sizeof(buffer), "%H:%M:%S", tm_info);
    return buffer;
}

/**
 * @brief Chat mesajını görüntüleme formatında hazırla
 */
char* format_chat_message_display(const char* sender_name, const char* message, time_t timestamp) {
    if (!sender_name || !message) return NULL;
    
    char* formatted_time = format_timestamp(timestamp);
    size_t total_len = strlen(sender_name) + strlen(message) + strlen(formatted_time) + 20;
    
    char* result = malloc(total_len);
    if (!result) return NULL;
    
    snprintf(result, total_len, "[%s] %s: %s", formatted_time, sender_name, message);
    return result;
}

/**
 * @brief Oda adını doğrula
 */
int validate_room_name(const char* room_name) {
    if (!room_name) return 0;
    
    size_t len = strlen(room_name);
    if (len == 0 || len >= MAX_ROOM_NAME_LEN) {
        return 0;
    }
    
    // İlk ve son karakter boşluk olamaz
    if (isspace(room_name[0]) || isspace(room_name[len - 1])) {
        return 0;
    }
    
    // Yasaklı karakterleri kontrol et
    for (size_t i = 0; i < len; i++) {
        char c = room_name[i];
        if (c == '<' || c == '>' || c == '"' || c == '\'' || 
            c == '&' || c == '|' || c == ';' || c == '\0') {
            return 0;
        }
    }
    
    return 1;
}

/**
 * @brief Kullanıcı ID listesini doğrula
 */
int validate_user_id_list(const char* user_id_list) {
    if (!user_id_list) return 0;
    
    size_t len = strlen(user_id_list);
    if (len == 0 || len >= MAX_USER_ID_LIST) {
        return 0;
    }
    
    // Sadece rakam ve virgül olabilir
    for (size_t i = 0; i < len; i++) {
        char c = user_id_list[i];
        if (!isdigit(c) && c != ',' && c != ' ') {
            return 0;
        }
    }
    
    // Ardışık virgül kontrolü
    for (size_t i = 0; i < len - 1; i++) {
        if (user_id_list[i] == ',' && user_id_list[i + 1] == ',') {
            return 0;
        }
    }
    
    return 1;
}

/**
 * @brief Mesajın geçerli olup olmadığını kontrol et
 */
int is_valid_message(const char* message) {
    if (!message) return 0;
    
    size_t len = strlen(message);
    if (len == 0 || len >= MAX_MESSAGE_LEN) {
        return 0;
    }
    
    // Sadece boşluk olan mesajları reddet
    int has_non_space = 0;
    for (size_t i = 0; i < len; i++) {
        if (!isspace(message[i])) {
            has_non_space = 1;
            break;
        }
    }
    
    return has_non_space;
}

/**
 * @brief Kullanıcının odaya erişim yetkisi olup olmadığını kontrol et
 * @details Bu fonksiyon chat_utils.h'da tanımlanan room_type enum'ları ile çalışır
 * @param user_id Kullanıcı ID'si
 * @param user_privilege Kullanıcı yetkisi (ADMIN_PRIVILEGE, vb.)
 * @param room Chat odası bilgileri
 * @return int Erişim yetkisi (1=izinli, 0=izinsiz)
 */
int chat_db_is_user_allowed_in_room(const char* user_id, int user_privilege, 
                                   const chat_room_t* room) {
    if (!user_id || !room) {
        return 0;
    }
    
    switch (room->room_type) {
        case ROOM_TYPE_EVERYONE:
            return 1; // Herkes katılabilir
            
        case ROOM_TYPE_ADMIN_ONLY:
            return (user_privilege == ADMIN_PRIVILEGE); // Sadece adminler
            
        case ROOM_TYPE_SPECIFIC_USERS:
            // Belirli kullanıcılar veya oda sahibi
            if (strcmp(user_id, room->creator_id) == 0) {
                return 1; // Oda sahibi
            }
            
            // Allowed user listesinde var mı kontrol et
            char search_pattern[128];
            snprintf(search_pattern, sizeof(search_pattern), ",%s,", user_id);
            
            // CSV listede ara (başına ve sonuna virgül ekleyerek)
            char padded_list[MAX_USER_ID_LIST + 4];
            snprintf(padded_list, sizeof(padded_list), ",%s,", room->allowed_user_ids);
            
            return (strstr(padded_list, search_pattern) != NULL);
            
        default:
            return 0;
    }
}

/**
 * @brief Chat room list'ini serbest bırak
 * @details Chat room list'inin dinamik belleğini güvenli şekilde serbest bırakır
 * @param list Serbest bırakılacak chat room list pointer'ı
 */
void chat_room_list_free(chat_room_list_t* list) {
    if (!list) return;
    
    if (list->rooms) {
        free(list->rooms);
    }
    
    free(list);
}