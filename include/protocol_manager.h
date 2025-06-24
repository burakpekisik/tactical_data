#ifndef PROTOCOL_MANAGER_H
#define PROTOCOL_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ecdh.h"
#include "config.h"
#include "encrypted_client.h"

char* create_normal_protocol_message(const char* filename, const char* content, const char* jwt_token);
char* create_encrypted_protocol_message(const char* filename, const char* content, const uint8_t* session_key, const char* jwt_token);
int send_tcp_message(client_connection_t* conn, const char* message);
int send_udp_message(client_connection_t* conn, const char* message);
int send_p2p_message(client_connection_t* conn, const char* message);
int receive_tcp_response(client_connection_t* conn, char* buffer, size_t buffer_size);
int receive_udp_response(client_connection_t* conn, char* buffer, size_t buffer_size);
int receive_p2p_response(client_connection_t* conn, char* buffer, size_t buffer_size);
void close_connection(client_connection_t* conn);

#endif /* PROTOCOL_MANAGER_H */