#ifndef HANDLE_MANAGER_H
#define HANDLE_MANAGER_H

#include <stdint.h>

void handle_signal(int sig);
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token, int client_socket, const char* client_ip, int client_port);
void* handle_client(void* arg);

#endif // HANDLE_MANAGER_H