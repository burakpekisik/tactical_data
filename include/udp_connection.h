#ifndef _UDP_CONNECTION_H_
#define _UDP_CONNECTION_H_

#include "connection_manager.h"
#include "crypto_utils.h"
#include <netinet/in.h>
#include <arpa/inet.h>

// UDP Client session yönetimi
typedef struct udp_session {
    char client_ip[INET_ADDRSTRLEN];
    int client_port;
    ecdh_context_t ecdh_ctx;
    bool ecdh_initialized;
    time_t last_activity;
    struct udp_session* next;
} udp_session_t;

// UDP Server fonksiyonları
int udp_server_init(connection_manager_t* manager);
int udp_server_start(connection_manager_t* manager);
int udp_server_stop(connection_manager_t* manager);
void* udp_server_thread(void* arg);
void udp_handle_packet(int socket, connection_manager_t* manager);

// UDP Client fonksiyonları
int udp_client_init(void);
int udp_client_send(int socket, const char* hostname, int port, const char* data, size_t length);
int udp_client_receive(int socket, char* buffer, size_t buffer_size, char* sender_ip, int* sender_port);
void udp_client_close(int socket);

// UDP Özel fonksiyonlar
int udp_broadcast_message(int socket, int port, const char* message);
int udp_multicast_join(int socket, const char* multicast_ip, int port);
int udp_multicast_leave(int socket, const char* multicast_ip);

// UDP İstatistik ve yönetim
void udp_update_stats(connection_manager_t* manager, bool packet_received);
void udp_log_packet(const char* client_ip, int client_port, size_t packet_size);

// UDP Mesaj işleme
int udp_parse_message(const char* message, const char* client_ip, int client_port, connection_manager_t* manager);
int udp_process_json_data(const char* json_data, const char* filename, const char* client_ip, int client_port);
int udp_process_encrypted_data(const char* encrypted_data, const char* filename, const char* client_ip, int client_port, const uint8_t* session_key, const char* jwt_token);

// UDP ECDH session yönetimi
udp_session_t* udp_find_session(const char* client_ip, int client_port);
udp_session_t* udp_create_session(const char* client_ip, int client_port);
void udp_cleanup_session(udp_session_t* session);
void udp_cleanup_old_sessions(void);
int udp_handle_key_exchange(int socket, struct sockaddr_in* client_addr, const char* message);
int udp_exchange_keys_with_client(udp_session_t* session, int socket, struct sockaddr_in* client_addr);

#endif // _UDP_CONNECTION_H_
