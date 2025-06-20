/**
 * @file tcp_connection.c
 * @brief TCP server/client bağlantı yönetimi
 * @ingroup tcp_networking
 * 
 * TCP tabanlı güvenilir tactical data iletişimi sağlar.
 * Multi-client server ve client connection management.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include "tcp_connection.h"
#include "config.h"
#include "thread_monitor.h"
#include "crypto_utils.h"
#include "json_utils.h"
#include "database.h"
#include "logger.h"

/// @brief External client handler function
void* handle_client(void* arg);
/// @brief External protocol parser function  
extern int parse_protocol_message(const char* message, char** command, char** filename, char** content);

/**
 * @brief TCP server'ı initialize eder
 * @param manager Connection manager
 * @return 0 başarı
 */
int tcp_server_init(connection_manager_t* manager) {
    PRINTF_LOG("TCP Server modülü başlatılıyor...\n");
    
    manager->type = CONN_TYPE_TCP;
    manager->status = CONN_STATUS_STOPPED;
    manager->server_fd = -1;
    manager->is_active = false;
    manager->client_count = 0;
    manager->total_connections = 0;
    manager->total_requests = 0;
    
    strcpy(manager->name, "TCP Server");
    
    PRINTF_LOG("✓ TCP Server modülü hazır (Port: %d)\n", manager->port);
    return 0;
}

/**
 * @brief TCP server'ı başlatır ve client connections kabul eder
 * @param manager Connection manager
 * @return 0 başarı, -1 hata
 */
int tcp_server_start(connection_manager_t* manager) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    PRINTF_LOG("TCP Server başlatılıyor (Port: %d)...\n", manager->port);
    
    // Socket oluştur
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("TCP Socket oluşturma hatası");
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    // Socket seçenekleri
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("TCP setsockopt hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    // Adres konfigürasyonu
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(manager->port);
    
    // Socket'i porta bağla
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("TCP Bind hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    // Dinlemeye başla
    if (listen(server_fd, CONFIG_MAX_CLIENTS) < 0) {
        perror("TCP Listen hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    manager->server_fd = server_fd;
    manager->status = CONN_STATUS_RUNNING;
    manager->is_active = true;
    
    // Server thread'ini başlat
    if (pthread_create(&manager->server_thread, NULL, tcp_server_thread, manager) != 0) {
        perror("TCP Thread oluşturma hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    pthread_detach(manager->server_thread);
    
    PRINTF_LOG("✓ TCP Server başarıyla başlatıldı (Port: %d)\n", manager->port);
    return 0;
}

/**
 * @brief TCP server'ı durdurur ve tüm connections kapatır
 * @param manager Connection manager
 * @return 0 başarı
 */
int tcp_server_stop(connection_manager_t* manager) {
    if (manager->status != CONN_STATUS_RUNNING) {
        PRINTF_LOG("TCP Server zaten durdurulmuş\n");
        return 0;
    }
    
    PRINTF_LOG("TCP Server durduruluyor...\n");
    manager->status = CONN_STATUS_STOPPING;
    
    // Önce tüm TCP client bağlantılarını sonlandır
    terminate_all_tcp_clients();
    
    // Server socket'ını kapat
    if (manager->server_fd >= 0) {
        shutdown(manager->server_fd, SHUT_RDWR);
        close(manager->server_fd);
        manager->server_fd = -1;
    }
    
    // Ana TCP server thread'inin durması için bekle
    sleep(1); // 1 saniye bekle
    
    manager->status = CONN_STATUS_STOPPED;
    manager->is_active = false;
    
    PRINTF_LOG("✓ TCP Server durduruldu (Port: %d)\n", manager->port);
    PRINTF_LOG("server> TCP Server thread sonlandırıldı\n");
    return 0;
}

/**
 * @brief TCP server ana thread - incoming connections kabul eder
 * @param arg Connection manager pointer
 * @return NULL
 */
void* tcp_server_thread(void* arg) {
    connection_manager_t* manager = (connection_manager_t*)arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    PRINTF_LOG("TCP Server thread başlatıldı (Port: %d)\n", manager->port);
    
    while (manager->is_active && manager->status == CONN_STATUS_RUNNING) {
        int client_socket = accept(manager->server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_socket < 0) {
            if (manager->is_active) {
                perror("TCP Accept hatası");
            }
            continue;
        }
        
        // Client IP'sini al
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);
        
        // Bağlantıyı logla
        tcp_log_connection(client_ip, client_port, true);
        
        // İstatistikleri güncelle
        tcp_update_stats(manager, true);
        
        // Client'ı handle etmek için thread oluştur
        int* client_socket_ptr = malloc(sizeof(int));
        *client_socket_ptr = client_socket;
        
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_client, client_socket_ptr) != 0) {
            perror("Client thread oluşturma hatası");
            close(client_socket);
            free(client_socket_ptr);
            tcp_update_stats(manager, false);
        } else {
            // Thread bilgisini monitor sistemine ekle
            add_thread_info(client_thread, client_socket, client_ip, client_port);
            pthread_detach(client_thread);
            PRINTF_LOG("TCP Thread added to monitor (ID: %lu, Socket: %d)\n", 
                   (unsigned long)client_thread, client_socket);
        }
    }
    
    PRINTF_LOG("TCP Server thread sonlandırıldı\n");
    return NULL;
}

/**
 * @brief TCP server'a client bağlantısı kurar
 * @param hostname Server IP adresi
 * @param port Server port numarası
 * @return Socket descriptor veya -1 hata
 */
int tcp_client_connect(const char* hostname, int port) {
    int client_socket;
    struct sockaddr_in server_addr;
    
    // Socket oluştur
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("TCP Client socket oluşturma hatası");
        return -1;
    }
    
    // Server adresini ayarla
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        perror("TCP Client geçersiz adres");
        close(client_socket);
        return -1;
    }
    
    // Bağlan
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP Client bağlantı hatası");
        close(client_socket);
        return -1;
    }
    
    PRINTF_LOG("TCP Client bağlandı (%s:%d)\n", hostname, port);
    return client_socket;
}

/**
 * @brief TCP connection üzerinden veri gönderir
 * @param socket Socket descriptor
 * @param data Gönderilecek veri
 * @param length Veri boyutu
 * @return Gönderilen byte sayısı veya -1 hata
 */
int tcp_client_send(int socket, const char* data, size_t length) {
    ssize_t bytes_sent = send(socket, data, length, 0);
    if (bytes_sent < 0) {
        perror("TCP Client veri gönderme hatası");
        return -1;
    }
    
    PRINTF_LOG("TCP Client veri gönderildi (%zd bytes)\n", bytes_sent);
    return bytes_sent;
}

/**
 * @brief TCP connection'dan veri alır
 * @param socket Socket descriptor
 * @param buffer Veri buffer'ı
 * @param buffer_size Buffer boyutu
 * @return Alınan byte sayısı veya -1 hata
 */
int tcp_client_receive(int socket, char* buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(socket, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        perror("TCP Client veri alma hatası");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    PRINTF_LOG("TCP Client veri alındı (%zd bytes)\n", bytes_received);
    return bytes_received;
}

/**
 * @brief TCP client bağlantısını kapatır
 * @param socket Socket descriptor
 */
void tcp_client_disconnect(int socket) {
    if (socket >= 0) {
        close(socket);
        PRINTF_LOG("TCP Client bağlantısı kapatıldı\n");
    }
}

/**
 * @brief TCP server connection istatistiklerini günceller
 * @param manager Connection manager
 * @param connection_added true: bağlantı eklendi, false: kaldırıldı
 */
void tcp_update_stats(connection_manager_t* manager, bool connection_added) {
    if (connection_added) {
        manager->client_count++;
        manager->total_connections++;
        PRINTF_LOG("TCP Stats: Active=%d, Total=%d\n", 
               manager->client_count, manager->total_connections);
    } else {
        if (manager->client_count > 0) {
            manager->client_count--;
        }
        PRINTF_LOG("TCP Stats: Active=%d, Total=%d\n", 
               manager->client_count, manager->total_connections);
    }
}

/**
 * @brief TCP client connection aktivitelerini loglar
 * @param client_ip Client IP adresi
 * @param client_port Client port numarası
 * @param connected true: bağlandı, false: ayrıldı
 */
void tcp_log_connection(const char* client_ip, int client_port, bool connected) {
    time_t now = time(NULL);
    char* time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // newline'ı kaldır
    
    PRINTF_LOG("[%s] TCP %s: %s:%d\n", 
           time_str, 
           connected ? "CONNECT" : "DISCONNECT", 
           client_ip, client_port);
}
