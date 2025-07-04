#ifndef CHAT_MANAGER_H
#define CHAT_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "encrypted_client.h"
#include "config.h"

// Chat room konfigürasyonu
#define MAX_ROOM_NAME_LEN 64
#define MAX_MESSAGE_LEN 512
#define MAX_ROOM_USERS 50
#define MAX_USER_ID_LIST 256
#define ROOM_KEY_SIZE 32  // AES256 için

// Chat room tipı
typedef enum {
    ROOM_TYPE_EVERYONE = 0,      // Herkes katılabilir
    ROOM_TYPE_ADMIN_ONLY = 1,    // Sadece adminler
    ROOM_TYPE_SPECIFIC_USERS = 2 // Belirli kullanıcılar
} chat_room_type_t;

// Chat room yapısı
typedef struct {
    int room_id;
    char room_name[MAX_ROOM_NAME_LEN];
    char creator_id[64];
    chat_room_type_t room_type;
    int max_users;
    int current_users;
    char allowed_user_ids[MAX_USER_ID_LIST]; // CSV format: "123,456,789"
    uint8_t room_key[ROOM_KEY_SIZE]; // Oda için paylaşılan şifreleme anahtarı
    time_t created_at;
    bool is_active;
} chat_room_t;

// Chat mesaj yapısı
typedef struct {
    int message_id;
    int room_id;
    char sender_id[64];
    char sender_name[128];
    char message[MAX_MESSAGE_LEN];
    time_t timestamp;
} chat_message_t;

// Chat room listesi yapısı
typedef struct {
    chat_room_t* rooms;
    int count;
    int capacity;
} chat_room_list_t;

// Chat room yönetimi
int create_chat_room_interactive(client_connection_t* conn, const char* jwt_token);
int list_and_join_chat_rooms(client_connection_t* conn, const char* jwt_token);
int enter_chat_session(client_connection_t* conn, const char* jwt_token, int room_id);
int join_chat_room_direct(client_connection_t* conn, const char* jwt_token, 
                         int room_id, const uint8_t* room_key);
int enter_chat_session_with_key(client_connection_t* conn, const char* jwt_token, int room_id, const uint8_t* room_key);
// Yardımcı fonksiyonlar
int get_room_type_from_user(void);
int get_max_users_from_user(void);
char* get_user_ids_from_user(void);
void print_room_info(const chat_room_t* room);

#endif // CHAT_MANAGER_H
