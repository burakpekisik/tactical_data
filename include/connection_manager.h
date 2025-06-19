#ifndef _CONNECTION_MANAGER_H_
#define _CONNECTION_MANAGER_H_

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

// Bağlantı türleri
typedef enum {
    CONN_TYPE_NONE = 0,
    CONN_TYPE_TCP = 1,
    CONN_TYPE_UDP = 2,
    CONN_TYPE_P2P = 3
} connection_type_t;

// Bağlantı durumları
typedef enum {
    CONN_STATUS_STOPPED = 0,
    CONN_STATUS_STARTING = 1,
    CONN_STATUS_RUNNING = 2,
    CONN_STATUS_STOPPING = 3,
    CONN_STATUS_ERROR = 4
} connection_status_t;

// Forward declaration
typedef struct connection_manager connection_manager_t;

// Bağlantı yöneticisi yapısı
struct connection_manager {
    connection_type_t type;
    connection_status_t status;
    int port;
    int server_fd;
    pthread_t server_thread;
    bool is_active;
    char name[64];
    
    // İstatistikler
    int client_count;
    int total_connections;
    int total_requests;
    
    // Callback fonksiyonları
    int (*start_func)(connection_manager_t*);
    int (*stop_func)(connection_manager_t*);
    void (*client_handler)(int socket, connection_type_t type);
};

// Function prototypes
int init_connection_manager(void);
int start_tcp_server(int port);
int stop_tcp_server(void);
int start_udp_server(int port);
int stop_udp_server(void);
int start_p2p_node(int port);
int stop_p2p_node(void);
void list_active_connections(void);
connection_status_t get_connection_status(connection_type_t type);
void show_connection_menu(void);
int process_connection_command(const char* command);
int stop_udp_server(void);
int start_p2p_node(int port);
int stop_p2p_node(void);

void list_active_connections(void);
connection_status_t get_connection_status(connection_type_t type);
int switch_connection_type(connection_type_t from_type, connection_type_t to_type);

// Kontrol arayüzü
void show_connection_menu(void);
int process_connection_command(const char* command);

#endif // _CONNECTION_MANAGER_H_
