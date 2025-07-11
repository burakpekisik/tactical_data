#ifndef CLIENT_LOGIN_USER_H
#define CLIENT_LOGIN_USER_H

#include <string.h>

char* client_login_to_server(const char* username, const char* password);
void handle_login_request(const char* buffer, int client_socket, pthread_t current_thread);

#endif // CLIENT_LOGIN_USER_H
