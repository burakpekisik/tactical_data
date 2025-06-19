#ifndef ENCRYPTED_CLIENT_H
#define ENCRYPTED_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ecdh.h"
#include "config.h"

// Connection types
typedef enum {
    CONN_TCP = 0,
    CONN_UDP = 1,
    CONN_P2P = 2
} connection_type_t;

typedef struct {
    int socket;
    connection_type_t type;
    int port;
    struct sockaddr_in server_addr;
    ecdh_context_t ecdh_ctx;
    bool ecdh_initialized;
} client_connection_t;

// Function prototypes
char* read_file_content(const char* filename, size_t* file_size);
char* create_normal_protocol_message(const char* filename, const char* content);
char* create_encrypted_protocol_message(const char* filename, const char* content, const uint8_t* session_key);
int send_json_file(client_connection_t* conn, const char* filename, int encrypt);
void handle_server_response(client_connection_t* conn);
void show_menu(void);
client_connection_t* connect_to_server(const char* server_host);
void close_connection(client_connection_t* conn);
int send_tcp_message(client_connection_t* conn, const char* message);
int send_udp_message(client_connection_t* conn, const char* message);
int send_p2p_message(client_connection_t* conn, const char* message);
int receive_tcp_response(client_connection_t* conn, char* buffer, size_t buffer_size);
int receive_udp_response(client_connection_t* conn, char* buffer, size_t buffer_size);
int receive_p2p_response(client_connection_t* conn, char* buffer, size_t buffer_size);

#endif /* ENCRYPTED_CLIENT_H */