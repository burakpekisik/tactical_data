/**
 * @file control_interface.c
 * @brief Sunucu kontrol arayüzü implementasyonu
 * @ingroup control_interface
 * 
 * TCP tabanlı sunucu yönetim komutları ve durum kontrolü.
 * Sunucuları başlatma/durdurma ve sistem istatistiklerini görüntüleme.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include "control_interface.h"
#include "connection_manager.h"
#include "config.h"
#include "thread_monitor.h"
#include "logger.h"

// Global control state
volatile int control_running = 0;
pthread_t control_thread_id;

/**
 * @brief Kontrol arayüzünü başlatır
 * @return 0 başarı, -1 hata
 * @ingroup control_interface
 */
int start_control_interface(void) {
    if (control_running) {
        PRINTF_LOG("Control interface already running\n");
        return 0;
    }
    
    PRINTF_LOG("Starting control interface on port %d\n", CONFIG_CONTROL_PORT);
    
    if (pthread_create(&control_thread_id, NULL, control_interface_thread, NULL) != 0) {
        perror("Control interface thread creation failed");
        return -1;
    }
    
    pthread_detach(control_thread_id);
    control_running = 1;
    PRINTF_LOG("✓ Control interface started (Port: %d)\n", CONFIG_CONTROL_PORT);
    return 0;
}

/**
 * @brief Kontrol arayüzünü durdurur
 * @ingroup control_interface
 */
void stop_control_interface(void) {
    if (!control_running) return;
    
    PRINTF_LOG("Stopping control interface...\n");
    control_running = 0;
    
    PRINTF_LOG("✓ Control interface stopped\n");
}

/**
 * @brief Kontrol arayüzü thread fonksiyonu
 * @param arg Thread parametresi (kullanılmıyor)
 * @return NULL
 * @ingroup control_interface
 */
void* control_interface_thread(void* arg) {
    (void)arg;
    
    int control_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (control_socket < 0) {
        perror("Control socket creation failed");
        control_running = 0;
        return NULL;
    }
    
    int opt = 1;
    setsockopt(control_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in control_addr = {0};
    control_addr.sin_family = AF_INET;
    control_addr.sin_addr.s_addr = INADDR_ANY;
    control_addr.sin_port = htons(CONFIG_CONTROL_PORT);
    
    if (bind(control_socket, (struct sockaddr*)&control_addr, sizeof(control_addr)) < 0) {
        perror("Control bind failed");
        close(control_socket);
        control_running = 0;
        return NULL;
    }
    
    if (listen(control_socket, 5) < 0) {
        perror("Control listen failed");
        close(control_socket);
        control_running = 0;
        return NULL;
    }
    
    PRINTF_LOG("Control interface listening on port %d\n", CONFIG_CONTROL_PORT);
    
    while (control_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_sock = accept(control_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (control_running) {
                perror("Control accept failed");
            }
            continue;
        }
        
        char command[256];
        memset(command, 0, sizeof(command));
        ssize_t bytes = read(client_sock, command, sizeof(command)-1);
        if (bytes > 0) {
            command[bytes] = '\0';
            // Remove newline
            char* newline = strchr(command, '\n');
            if (newline) *newline = '\0';
            
            PRINTF_LOG("Control command received: '%s'\n", command);
            handle_control_command(command, client_sock);
        }
        
        close(client_sock);
    }
    
    close(control_socket);
    PRINTF_LOG("Control interface thread ended\n");
    return NULL;
}

/**
 * @brief Kontrol komutlarını işler ve yanıt verir
 * @param command Gelen komut string'i
 * @param response_socket Yanıt göndermek için socket
 * @ingroup control_interface
 */
void handle_control_command(const char* command, int response_socket) {
    char response[1024];
    
    if (strcmp(command, "list") == 0) {
        snprintf(response, sizeof(response), 
                "=== SERVER STATUS ===\n"
                "TCP Server: %s (Port: %d)\n"
                "UDP Server: %s (Port: %d)\n"
                "P2P Node: %s (Port: %d)\n"
                "Control Interface: %s (Port: %d)\n"
                "Active Threads: %d\n"
                "====================\n",
                get_connection_status(CONN_TYPE_TCP) == CONN_STATUS_RUNNING ? "RUNNING" : "STOPPED", CONFIG_PORT,
                get_connection_status(CONN_TYPE_UDP) == CONN_STATUS_RUNNING ? "RUNNING" : "STOPPED", CONFIG_UDP_PORT,
                get_connection_status(CONN_TYPE_P2P) == CONN_STATUS_RUNNING ? "RUNNING" : "STOPPED", CONFIG_P2P_PORT,
                control_running ? "RUNNING" : "STOPPED", CONFIG_CONTROL_PORT,
                get_active_thread_count());
    }
    else if (strcmp(command, "stop_tcp") == 0) {
        if (get_connection_status(CONN_TYPE_TCP) == CONN_STATUS_RUNNING) {
            stop_tcp_server();
            snprintf(response, sizeof(response), "✓ TCP Server stopped\n");
        } else {
            snprintf(response, sizeof(response), "✗ TCP Server already stopped\n");
        }
    }
    else if (strcmp(command, "start_tcp") == 0) {
        if (get_connection_status(CONN_TYPE_TCP) != CONN_STATUS_RUNNING) {
            if (start_tcp_server(CONFIG_PORT) == 0) {
                snprintf(response, sizeof(response), "✓ TCP Server started\n");
            } else {
                snprintf(response, sizeof(response), "✗ TCP Server start failed\n");
            }
        } else {
            snprintf(response, sizeof(response), "✗ TCP Server already running\n");
        }
    }
    else if (strcmp(command, "stop_udp") == 0) {
        if (get_connection_status(CONN_TYPE_UDP) == CONN_STATUS_RUNNING) {
            stop_udp_server();
            snprintf(response, sizeof(response), "✓ UDP Server stopped\n");
        } else {
            snprintf(response, sizeof(response), "✗ UDP Server already stopped\n");
        }
    }
    else if (strcmp(command, "start_udp") == 0) {
        if (get_connection_status(CONN_TYPE_UDP) != CONN_STATUS_RUNNING) {
            if (start_udp_server(CONFIG_UDP_PORT) == 0) {
                snprintf(response, sizeof(response), "✓ UDP Server started\n");
            } else {
                snprintf(response, sizeof(response), "✗ UDP Server start failed\n");
            }
        } else {
            snprintf(response, sizeof(response), "✗ UDP Server already running\n");
        }
    }
    else if (strcmp(command, "start_p2p") == 0) {
        if (get_connection_status(CONN_TYPE_P2P) != CONN_STATUS_RUNNING) {
            if (start_p2p_node(CONFIG_P2P_PORT) == 0) {
                snprintf(response, sizeof(response), "✓ P2P Node started\n");
            } else {
                snprintf(response, sizeof(response), "✗ P2P Node start failed\n");
            }
        } else {
            snprintf(response, sizeof(response), "✗ P2P Node already running\n");
        }
    }
    else if (strcmp(command, "stop_p2p") == 0) {
        if (get_connection_status(CONN_TYPE_P2P) == CONN_STATUS_RUNNING) {
            stop_p2p_node();
            snprintf(response, sizeof(response), "✓ P2P Node stopped\n");
        } else {
            snprintf(response, sizeof(response), "✗ P2P Node already stopped\n");
        }
    }
    else if (strcmp(command, "stats") == 0) {
        snprintf(response, sizeof(response), 
                "=== STATISTICS ===\n"
                "Active Threads: %d/%d\n"
                "Total Connections: %d\n"
                "==================\n",
                get_active_thread_count(), CONFIG_MAX_CLIENTS,
                get_total_connections());
    }
    else if (strcmp(command, "help") == 0) {
        snprintf(response, sizeof(response), 
                "=== AVAILABLE COMMANDS ===\n"
                "list         - Show server status\n"
                "start_tcp    - Start TCP server\n"
                "stop_tcp     - Stop TCP server\n"
                "start_udp    - Start UDP server\n"
                "stop_udp     - Stop UDP server\n"
                "start_p2p    - Start P2P node\n"
                "stop_p2p     - Stop P2P node\n"
                "stats        - Show statistics\n"
                "healthcheck  - Health check (Docker)\n"
                "help         - Show this help\n"
                "quit         - Close connection\n"
                "==========================\n");
    }
    else if (strcmp(command, "quit") == 0) {
        snprintf(response, sizeof(response), "Goodbye!\n");
    }
    else if (strcmp(command, "healthcheck") == 0 || strcmp(command, "ping") == 0) {
        // Health check için basit response - counter'ı artır
        increment_healthcheck_count();
        snprintf(response, sizeof(response), "HEALTHY\n");
        PRINTF_LOG(" HEALTHCHECK: Docker health check received\n");
    }
    else {
        snprintf(response, sizeof(response), 
                "Unknown command: '%s'\n"
                "Type 'help' for available commands\n", command);
    }
    
    write(response_socket, response, strlen(response));
}
