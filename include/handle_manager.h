#ifndef HANDLE_MANAGER_H
#define HANDLE_MANAGER_H

#include <stdint.h>
#include "config.h"

typedef struct {
    int room_id;
    int participant_sockets[MAX_ROOM_PARTICIPANTS];
    int participant_count;
} server_chat_room_t;

void handle_signal(int sig);
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token, int client_socket, const char* client_ip, int client_port);
void* handle_client(void* arg);
char* handle_chat_send_message(const char* decrypted_json, const char* jwt_token);
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token, int client_socket, const char* client_ip, int client_port);
char* handle_chat_create_room(const char* decrypted_json, const char* jwt_token);
char* handle_chat_list_rooms(const char* decrypted_json, const char* jwt_token);
char* encrypt_and_format_response(const char* plain_json, const uint8_t* session_key, const char* action_name);
char* handle_chat_join_room(const char* decrypted_json, const char* jwt_token);
void add_socket_to_room(int room_id, int client_socket);
void broadcast_message_to_room(int room_id, const char* plain_json, int exclude_socket);
#endif // HANDLE_MANAGER_H