#ifndef HANDLE_MANAGER_H
#define HANDLE_MANAGER_H

#include <stdint.h>
#include "config.h"
#include "connection_manager.h"

typedef struct {
    int room_id;
    int participant_sockets[MAX_ROOM_PARTICIPANTS];
    int participant_count;
} server_chat_room_t;

void handle_signal(int sig);
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token, int client_socket, const char* client_ip, int client_port);
void* handle_client(void* arg);
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token, int client_socket, const char* client_ip, int client_port);
char* encrypt_and_format_response(const char* plain_json, const uint8_t* session_key, const char* action_name);
void handle_login_request(const char* buffer, int client_socket, pthread_t current_thread);
int handle_ecdh_key_exchange(int client_socket, pthread_t current_thread, connection_manager_t* client_manager, uint8_t* client_public_key, char* buffer, ssize_t bytes_received);
void* admin_notify_listener_thread(void* arg);

#endif // HANDLE_MANAGER_H