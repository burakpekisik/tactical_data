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

extern struct report_reply_entry report_replies[MAX_REPORT_REPLIES];
extern int report_reply_count;
extern pthread_mutex_t report_reply_mutex;

void handle_server_response(client_connection_t* conn);
void show_menu(void);
client_connection_t* connect_to_server(const char* server_host);

int send_hello_after_ecdh(client_connection_t* conn, const char* jwt_token);

// Load balancer functions
void close_connection(client_connection_t* conn);


#endif /* ENCRYPTED_CLIENT_H */