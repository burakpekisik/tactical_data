// large_response.h

#ifndef LARGE_RESPONSE_H
#define LARGE_RESPONSE_H

#include <stdint.h>

void send_large_plain_response(int client_socket, const char* command, const char* data);
void send_large_encrypted_response(int client_socket, const char* hex_data);
// Büyük şifreli yanıtı tek parça veya parça parça gönderen fonksiyonun prototipi
char* send_or_format_large_encrypted_response(int client_socket, const char* plain_result, const uint8_t* session_key, const char* filename);

#endif // LARGE_RESPONSE_H