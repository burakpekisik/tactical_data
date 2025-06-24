#ifndef FALLBACK_MANAGER_H
#define FALLBACK_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ecdh.h"
#include "config.h"
#include "encrypted_client.h"

// Fallback functions
const char* get_connection_type_name(connection_type_t type);
int try_send_message_current_connection(client_connection_t* conn, const char* message);
int try_send_message_with_fallback(client_connection_t* conn, const char* protocol_message, 
                                   const char* filename, const char* content, int encrypt, const char* jwt_token);
client_connection_t* create_fallback_connection(client_connection_t* original_conn, connection_type_t target_type);
bool setup_ecdh_for_fallback(client_connection_t* conn);
bool setup_udp_ecdh_for_fallback(client_connection_t* conn);
char* adapt_message_for_protocol(const char* original_message, connection_type_t target_type);
void update_main_connection_from_fallback(client_connection_t* main_conn, client_connection_t* fallback_conn);

#endif /* FALLBACK_MANAGER_H */