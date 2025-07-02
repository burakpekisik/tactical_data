#ifndef LARGE_RESPONSE_H
#define LARGE_RESPONSE_H

void send_large_plain_response(int client_socket, const char* command, const char* data);
void send_large_encrypted_response(int client_socket, const char* hex_data);

#endif // LARGE_RESPONSE_H