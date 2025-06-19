#ifndef _TCP_CONNECTION_H_
#define _TCP_CONNECTION_H_

#include "connection_manager.h"

// TCP Server fonksiyonları
int tcp_server_init(connection_manager_t* manager);
int tcp_server_start(connection_manager_t* manager);
int tcp_server_stop(connection_manager_t* manager);
void* tcp_server_thread(void* arg);
void tcp_handle_client(int client_socket, connection_manager_t* manager);

// TCP Client fonksiyonları
int tcp_client_connect(const char* hostname, int port);
int tcp_client_send(int socket, const char* data, size_t length);
int tcp_client_receive(int socket, char* buffer, size_t buffer_size);
void tcp_client_disconnect(int socket);

// TCP İstatistik ve yönetim
void tcp_update_stats(connection_manager_t* manager, bool connection_added);
void tcp_log_connection(const char* client_ip, int client_port, bool connected);

#endif // _TCP_CONNECTION_H_
