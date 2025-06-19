#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "connection_manager.h"
#include "tcp_connection.h"
#include "udp_connection.h"
#include "p2p_connection.h"
#include "config.h"

// Global connection managers
static connection_manager_t tcp_manager;
static connection_manager_t udp_manager;
static connection_manager_t p2p_manager;

static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool manager_initialized = false;

// Connection manager'ı başlat
int init_connection_manager(void) {
    pthread_mutex_lock(&conn_mutex);
    
    if (manager_initialized) {
        pthread_mutex_unlock(&conn_mutex);
        return 0;
    }
    
    // TCP Manager
    memset(&tcp_manager, 0, sizeof(connection_manager_t));
    tcp_manager.port = CONFIG_PORT;
    tcp_server_init(&tcp_manager);
    
    // UDP Manager
    memset(&udp_manager, 0, sizeof(connection_manager_t));
    udp_manager.port = CONFIG_PORT + 1;
    udp_server_init(&udp_manager);
    
    // P2P Manager
    memset(&p2p_manager, 0, sizeof(connection_manager_t));
    p2p_manager.port = CONFIG_PORT + 2;
    p2p_node_init(&p2p_manager);
    
    manager_initialized = true;
    pthread_mutex_unlock(&conn_mutex);
    
    printf("Connection Manager initialized\n");
    printf("- TCP: Port %d (Ready)\n", tcp_manager.port);
    printf("- UDP: Port %d (Ready)\n", udp_manager.port);
    printf("- P2P: Port %d (Ready)\n", p2p_manager.port);
    fflush(stdout);
    
    return 0;
}

// TCP Server başlat
int start_tcp_server(int port) {
    pthread_mutex_lock(&conn_mutex);
    
    if (tcp_manager.status == CONN_STATUS_RUNNING) {
        printf("TCP Server zaten çalışıyor (Port: %d)\n", tcp_manager.port);
        pthread_mutex_unlock(&conn_mutex);
        return 0;
    }
    
    tcp_manager.port = port;
    int result = tcp_server_start(&tcp_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// TCP Server durdur
int stop_tcp_server(void) {
    pthread_mutex_lock(&conn_mutex);
    
    int result = tcp_server_stop(&tcp_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// UDP Server başlat
int start_udp_server(int port) {
    pthread_mutex_lock(&conn_mutex);
    
    if (udp_manager.status == CONN_STATUS_RUNNING) {
        printf("UDP Server zaten çalışıyor (Port: %d)\n", udp_manager.port);
        pthread_mutex_unlock(&conn_mutex);
        return 0;
    }
    
    udp_manager.port = port;
    int result = udp_server_start(&udp_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// UDP Server durdur
int stop_udp_server(void) {
    pthread_mutex_lock(&conn_mutex);
    
    int result = udp_server_stop(&udp_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// P2P Node başlat
int start_p2p_node(int port) {
    pthread_mutex_lock(&conn_mutex);
    
    if (p2p_manager.status == CONN_STATUS_RUNNING) {
        printf("P2P Node zaten çalışıyor (Port: %d)\n", p2p_manager.port);
        pthread_mutex_unlock(&conn_mutex);
        return 0;
    }
    
    p2p_manager.port = port;
    int result = p2p_node_start(&p2p_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// P2P Node durdur
int stop_p2p_node(void) {
    pthread_mutex_lock(&conn_mutex);
    
    int result = p2p_node_stop(&p2p_manager);
    
    pthread_mutex_unlock(&conn_mutex);
    return result;
}

// Aktif bağlantıları listele
void list_active_connections(void) {
    pthread_mutex_lock(&conn_mutex);
    
    printf("\n==== ACTIVE CONNECTIONS ====\n");
    
    // TCP Status
    printf("TCP Server: %s (Port: %d, Status: %s)\n",
           tcp_manager.is_active ? "ACTIVE" : "INACTIVE",
           tcp_manager.port,
           tcp_manager.status == CONN_STATUS_RUNNING ? "RUNNING" :
           tcp_manager.status == CONN_STATUS_STOPPED ? "STOPPED" :
           tcp_manager.status == CONN_STATUS_ERROR ? "ERROR" : "UNKNOWN");
    
    // UDP Status
    printf("UDP Server: %s (Port: %d, Status: %s)\n",
           udp_manager.is_active ? "ACTIVE" : "INACTIVE",
           udp_manager.port,
           udp_manager.status == CONN_STATUS_RUNNING ? "RUNNING" :
           udp_manager.status == CONN_STATUS_STOPPED ? "STOPPED" :
           udp_manager.status == CONN_STATUS_ERROR ? "ERROR" : "UNKNOWN");
    
    // P2P Status
    printf("P2P Node: %s (Port: %d, Status: %s)\n",
           p2p_manager.is_active ? "ACTIVE" : "INACTIVE",
           p2p_manager.port,
           p2p_manager.status == CONN_STATUS_RUNNING ? "RUNNING" :
           p2p_manager.status == CONN_STATUS_STOPPED ? "STOPPED" :
           p2p_manager.status == CONN_STATUS_ERROR ? "ERROR" : "UNKNOWN");
    
    printf("============================\n\n");
    
    pthread_mutex_unlock(&conn_mutex);
}

// Bağlantı durumunu al
connection_status_t get_connection_status(connection_type_t type) {
    pthread_mutex_lock(&conn_mutex);
    
    connection_status_t status = CONN_STATUS_STOPPED;
    
    switch (type) {
        case CONN_TYPE_TCP:
            status = tcp_manager.status;
            break;
        case CONN_TYPE_UDP:
            status = udp_manager.status;
            break;
        case CONN_TYPE_P2P:
            status = p2p_manager.status;
            break;
        default:
            break;
    }
    
    pthread_mutex_unlock(&conn_mutex);
    return status;
}

// Connection menüsü
void show_connection_menu(void) {
    printf("\n=== CONNECTION CONTROL MENU ===\n");
    printf("TCP Commands:\n");
    printf("  start_tcp  - Start TCP Server\n");
    printf("  stop_tcp   - Stop TCP Server\n");
    printf("UDP Commands:\n");
    printf("  start_udp  - Start UDP Server\n");
    printf("  stop_udp   - Stop UDP Server\n");
    printf("P2P Commands:\n");
    printf("  start_p2p  - Start P2P Node\n");
    printf("  stop_p2p   - Stop P2P Node\n");
    printf("General Commands:\n");
    printf("  list       - List Active Connections\n");
    printf("  stats      - Show Statistics\n");
    printf("  help       - Show this menu\n");
    printf("  quit       - Exit server\n");
    printf("===============================\n");
}

// Command işleme
int process_connection_command(const char* command) {
    if (strcmp(command, "start_tcp") == 0) {
        return start_tcp_server(CONFIG_PORT);
    } else if (strcmp(command, "stop_tcp") == 0) {
        return stop_tcp_server();
    } else if (strcmp(command, "start_udp") == 0) {
        return start_udp_server(CONFIG_PORT + 1);
    } else if (strcmp(command, "stop_udp") == 0) {
        return stop_udp_server();
    } else if (strcmp(command, "start_p2p") == 0) {
        return start_p2p_node(CONFIG_PORT + 2);
    } else if (strcmp(command, "stop_p2p") == 0) {
        return stop_p2p_node();
    } else if (strcmp(command, "list") == 0) {
        list_active_connections();
        return 0;
    }
    
    return -1;
}
