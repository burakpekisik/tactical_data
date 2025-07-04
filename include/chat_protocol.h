#ifndef CHAT_PROTOCOL_H
#define CHAT_PROTOCOL_H

#include "chat_manager.h"
#include "encrypted_client.h"

// Chat protokol mesaj tipleri
typedef enum {
    CHAT_MSG_CREATE_ROOM = 101,
    CHAT_MSG_LIST_ROOMS = 102,
    CHAT_MSG_JOIN_ROOM = 103,
    CHAT_MSG_LEAVE_ROOM = 104,
    CHAT_MSG_SEND_MESSAGE = 105,
    CHAT_MSG_GET_MESSAGES = 106,
    CHAT_MSG_ROOM_KEY_REQUEST = 107,
    CHAT_MSG_ROOM_KEY_RESPONSE = 108
} chat_message_type_t;

// Chat protokol fonksiyonları
int send_create_room_request(client_connection_t* conn, const char* jwt_token, 
                           const char* room_name, chat_room_type_t room_type, 
                           int max_users, const char* allowed_user_ids);

int send_list_rooms_request(client_connection_t* conn, const char* jwt_token);
chat_room_list_t* receive_room_list(client_connection_t* conn);

// --- CHAT ENCRYPTED PROTOCOL ---
int send_encrypted_chat_action(client_connection_t* conn, const char* action_name, const char* json_string, const char* jwt_token);

int send_join_room_request(client_connection_t* conn, const char* jwt_token, int room_id);
int send_leave_room_request(client_connection_t* conn, const char* jwt_token, int room_id);

int send_chat_message(client_connection_t* conn, const char* jwt_token, 
                     int room_id, const char* message, const uint8_t* room_key);

int receive_chat_messages(client_connection_t* conn, const char* jwt_token, 
                         int room_id, const uint8_t* room_key);

uint8_t* receive_room_key(client_connection_t* conn, const char* jwt_token, int room_id);

// Şifreleme yardımcı fonksiyonları
int encrypt_chat_message(const char* message, const uint8_t* room_key, 
                        char** encrypted_message, size_t* encrypted_len);
int decrypt_chat_message(const char* encrypted_message, size_t encrypted_len, 
                        const uint8_t* room_key, char** decrypted_message);
int send_encrypted_data_with_response(client_connection_t* conn, const char* data, size_t data_len);
char* receive_encrypted_response(client_connection_t* conn);
int send_encrypted_data(client_connection_t* conn, const char* data, size_t data_len);
void flush_socket(int sockfd);
char* receive_encrypted_response_room_key(client_connection_t* conn, const uint8_t* room_key);

#endif // CHAT_PROTOCOL_H
