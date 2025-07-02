#ifndef ENCRYPTED_CLIENT_H
#define ENCRYPTED_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "crypto_utils.h"
#include "config.h"
#include "connection_manager.h"

typedef struct {
    int socket;
    connection_type_t type;
    int port;
    struct sockaddr_in server_addr;
    ecdh_context_t ecdh_ctx;
    bool ecdh_initialized;
} client_connection_t;

// Gelen admin cevaplarını saklamak için yapı
struct report_reply_entry {
    int report_id;
    char msg[900];
};

// Function prototypes
char* read_file_content(const char* filename, size_t* file_size);

void handle_server_response(client_connection_t* conn);
void show_menu(void);
client_connection_t* connect_to_server(const char* server_host);
void listen_for_admin_notifications(client_connection_t* conn);
void* report_reply_listener_thread(void* arg);
void* admin_reply_input_thread(void* arg);
void watch_report_replies(client_connection_t* conn);
int send_hello_after_ecdh(client_connection_t* conn, const char* jwt_token);
void query_my_replies_with_jwt(client_connection_t* conn, const char* jwt_token);
int admin_reply_to_report(client_connection_t* conn, const char* jwt_token);
ssize_t recv_full(int sock, char* buf, size_t maxlen);
int send_json_file(client_connection_t* conn, const char* filename, int encrypt, const char* jwt_token);
void query_my_replies(client_connection_t* conn, const char* jwt_token);
void query_replies_to_one_report(client_connection_t* conn, const char* jwt_token);


#endif /* ENCRYPTED_CLIENT_H */