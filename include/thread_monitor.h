#ifndef _THREAD_MONITOR_H_
#define _THREAD_MONITOR_H_

#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include "config.h"

// Thread istatistikleri için yapı
typedef struct {
    pthread_t thread_id;
    int client_socket;
    time_t start_time;
    char client_ip[INET_ADDRSTRLEN];
    int client_port;
    int is_active;
    char thread_name[CONFIG_MAX_THREAD_NAME];
} thread_info_t;

// Queue için client bilgileri
typedef struct queue_client {
    int client_socket;
    struct sockaddr_in client_addr;
    time_t queue_time;
    struct queue_client* next;
} queue_client_t;

void log_thread_stats(void);
void add_thread_info(pthread_t thread_id, int client_socket, const char* client_ip, int client_port);
void remove_thread_info(pthread_t thread_id);
void terminate_all_tcp_clients(void);
void* thread_monitor(void* arg);
int get_active_thread_count(void);
int get_total_connections(void);
void increment_healthcheck_count(void);
int get_healthcheck_count(void);
void increment_udp_connection(void);
void increment_total_connections(void);
void init_thread_monitoring(void);
void log_thread_stats(void);

// Queue fonksiyonları
void add_to_queue(int client_socket, struct sockaddr_in client_addr);
int process_queue(void);
int get_queue_size(void);
void log_queue_stats(void);
void clear_queue(void);

// Forward declaration - encrypted_server.c'de tanımlanacak
void* handle_client(void* arg);

#endif // _THREAD_MONITOR_H_