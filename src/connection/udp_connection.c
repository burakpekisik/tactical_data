#define _GNU_SOURCE
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
#include <sys/types.h>
#include <netdb.h>
#include "udp_connection.h"
#include "config.h"
#include "thread_monitor.h"
#include "json_utils.h"
#include "crypto_utils.h"
#include "database.h"

// UDP Server başlatma
int udp_server_init(connection_manager_t* manager) {
    printf("UDP Server modülü başlatılıyor...\n");
    
    manager->type = CONN_TYPE_UDP;
    manager->status = CONN_STATUS_STOPPED;
    manager->server_fd = -1;
    manager->is_active = false;
    manager->client_count = 0;
    manager->total_connections = 0;
    manager->total_requests = 0;
    
    strcpy(manager->name, "UDP Server");
    
    printf("✓ UDP Server modülü hazır (Port: %d)\n", manager->port);
    return 0;
}

// UDP Server başlat
int udp_server_start(connection_manager_t* manager) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    printf("UDP Server başlatılıyor (Port: %d)...\n", manager->port);
    
    // Socket oluştur
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) == 0) {
        perror("UDP Socket oluşturma hatası");
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    // Socket seçenekleri
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("UDP setsockopt hatası");
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
        perror("UDP Bind hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    manager->server_fd = server_fd;
    manager->status = CONN_STATUS_RUNNING;
    manager->is_active = true;
    
    // Server thread'ini başlat
    if (pthread_create(&manager->server_thread, NULL, udp_server_thread, manager) != 0) {
        perror("UDP Thread oluşturma hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    pthread_detach(manager->server_thread);
    
    printf("✓ UDP Server başarıyla başlatıldı (Port: %d)\n", manager->port);
    return 0;
}

// UDP Server durdur
int udp_server_stop(connection_manager_t* manager) {
    if (manager->status != CONN_STATUS_RUNNING) {
        printf("UDP Server zaten durdurulmuş\n");
        return 0;
    }
    
    printf("UDP Server durduruluyor...\n");
    manager->status = CONN_STATUS_STOPPING;
    
    // Server socket'ını kapat
    if (manager->server_fd >= 0) {
        close(manager->server_fd);
        manager->server_fd = -1;
    }
    
    manager->status = CONN_STATUS_STOPPED;
    manager->is_active = false;
    
    printf("✓ UDP Server durduruldu (Port: %d)\n", manager->port);
    return 0;
}

// UDP Server ana thread
void* udp_server_thread(void* arg) {
    connection_manager_t* manager = (connection_manager_t*)arg;
    char buffer[CONFIG_BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    printf("UDP Server thread başlatıldı (Port: %d)\n", manager->port);
    
    while (manager->is_active && manager->status == CONN_STATUS_RUNNING) {
        memset(buffer, 0, CONFIG_BUFFER_SIZE);
        
        ssize_t bytes_received = recvfrom(manager->server_fd, buffer, CONFIG_BUFFER_SIZE - 1, 0,
                                         (struct sockaddr*)&client_addr, &client_len);
        
        if (bytes_received < 0) {
            if (manager->is_active) {
                perror("UDP Receive hatası");
            }
            continue;
        }
        
        // Client IP'sini al
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);
        
        // Paketi logla
        udp_log_packet(client_ip, client_port, bytes_received);
        
        // İstatistikleri güncelle
        udp_update_stats(manager, true);
        
        // UDP packet'i için connection sayısını artır
        manager->total_connections++;
        increment_udp_connection();
        
        // Paketi işle
        buffer[bytes_received] = '\0';
        
        // JSON mesaj parsing (Tactical Data formatı)
        if (udp_parse_message(buffer, client_ip, client_port, manager) == 0) {
            // Başarılı parsing sonrası response gönder
            const char* response = "UDP_SUCCESS: Message processed";
            sendto(manager->server_fd, response, strlen(response), 0,
                   (struct sockaddr*)&client_addr, client_len);
        } else {
            // Parse hatası durumunda hata mesajı gönder
            const char* error_response = "UDP_ERROR: Invalid message format";
            sendto(manager->server_fd, error_response, strlen(error_response), 0,
                   (struct sockaddr*)&client_addr, client_len);
        }
    }
    
    printf("UDP Server thread sonlandırıldı\n");
    return NULL;
}

// UDP Client başlatma
int udp_client_init(void) {
    int client_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_socket < 0) {
        perror("UDP Client socket oluşturma hatası");
        return -1;
    }
    
    printf("UDP Client socket oluşturuldu\n");
    return client_socket;
}

// UDP Client veri gönderme
int udp_client_send(int socket, const char* hostname, int port, const char* data, size_t length) {
    struct sockaddr_in server_addr;
    
    // Server adresini ayarla
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        perror("UDP Client geçersiz adres");
        return -1;
    }
    
    // Veriyi gönder
    ssize_t bytes_sent = sendto(socket, data, length, 0,
                               (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    if (bytes_sent < 0) {
        perror("UDP Client veri gönderme hatası");
        return -1;
    }
    
    printf("UDP Client veri gönderildi (%s:%d, %zd bytes)\n", hostname, port, bytes_sent);
    return bytes_sent;
}

// UDP Client veri alma
int udp_client_receive(int socket, char* buffer, size_t buffer_size, char* sender_ip, int* sender_port) {
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    
    ssize_t bytes_received = recvfrom(socket, buffer, buffer_size - 1, 0,
                                     (struct sockaddr*)&sender_addr, &sender_len);
    
    if (bytes_received < 0) {
        perror("UDP Client veri alma hatası");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    
    // Gönderen bilgilerini ayarla
    if (sender_ip) {
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, INET_ADDRSTRLEN);
    }
    if (sender_port) {
        *sender_port = ntohs(sender_addr.sin_port);
    }
    
    printf("UDP Client veri alındı (%zd bytes)\n", bytes_received);
    return bytes_received;
}

// UDP Client kapatma
void udp_client_close(int socket) {
    if (socket >= 0) {
        close(socket);
        printf("UDP Client socket kapatıldı\n");
    }
}

// UDP İstatistiklerini güncelle
void udp_update_stats(connection_manager_t* manager, bool packet_received) {
    if (packet_received) {
        manager->total_requests++;
        printf("UDP Stats: Total packets=%d\n", manager->total_requests);
    }
}

// UDP Paket logla
void udp_log_packet(const char* client_ip, int client_port, size_t packet_size) {
    time_t now = time(NULL);
    char* time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // newline'ı kaldır
    
    printf("[%s] UDP PACKET: %s:%d (%zu bytes)\n", 
           time_str, client_ip, client_port, packet_size);
}

// UDP Mesaj parsing
int udp_parse_message(const char* message, const char* client_ip, int client_port, connection_manager_t* manager) {
    printf("UDP Mesaj parsing: %s (kaynak: %s:%d)\n", message, client_ip, client_port);
    
    // Protokol mesajini parse et (PARSE:filename:content veya ENCRYPTED:filename:content)
    char *message_copy = strdup(message);
    if (!message_copy) {
        printf("UDP Parse Error: Memory allocation failed\n");
        return -1;
    }
    
    char *command = strtok(message_copy, ":");
    char *filename = strtok(NULL, ":");
    char *content = strtok(NULL, "\0"); // Geri kalan kısmı al
    
    if (!command || !filename || !content) {
        printf("UDP Parse Error: Invalid protocol format\n");
        free(message_copy);
        return -1;
    }
    
    printf("UDP Command: %s, File: %s\n", command, filename);
    
    int result = -1;
    
    if (strcmp(command, "PARSE") == 0) {
        printf("UDP Normal JSON parse ediliyor...\n");
        result = udp_process_json_data(content, filename, client_ip, client_port);
    } else if (strcmp(command, "ENCRYPTED") == 0) {
        printf("UDP Encrypted JSON parse ediliyor...\n");
        result = udp_process_encrypted_data(content, filename, client_ip, client_port);
    } else {
        printf("UDP Parse Error: Unknown command: %s\n", command);
    }
    
    manager->total_requests++;
    free(message_copy);
    return result;
}

// UDP JSON data işleme - TCP'deki gibi gerçek processing
int udp_process_json_data(const char* json_data, const char* filename, const char* client_ip, int client_port) {
    printf("UDP JSON Processing: %s from %s:%d\n", filename, client_ip, client_port);
    
    // JSON'u tactical data struct'ına parse et (TCP'deki gibi)
    tactical_data_t* tactical_data = parse_json_to_tactical_data(json_data, filename);
    if (tactical_data != NULL && tactical_data->is_valid) {
        printf("UDP: Tactical data parsed successfully\n");
        
        // Database'e kaydet
        char* response = db_save_tactical_data_and_get_response(tactical_data, filename);
        if (response) {
            printf("UDP: Database save response: %s\n", response);
            free(response);
        }
        
        free_tactical_data(tactical_data);
        
        printf("UDP JSON Success: Data saved to database for %s\n", filename);
        return 0;
    } else {
        printf("UDP JSON Error: Invalid tactical data format\n");
        if (tactical_data) free_tactical_data(tactical_data);
        return -1;
    }
}

// UDP Encrypted data işleme
int udp_process_encrypted_data(const char* encrypted_data, const char* filename, const char* client_ip, int client_port) {
    printf("UDP Encrypted Processing: %s from %s:%d\n", filename, client_ip, client_port);
    
    // Hex data'yı decode et - standart crypto_utils fonksiyonunu kullan
    size_t binary_len;
    uint8_t* binary_data = hex_to_bytes(encrypted_data, &binary_len);
    if (!binary_data) {
        printf("UDP Encrypted Error: Hex decode failed\n");
        return -1;
    }
    
    // Decrypt data - IV ilk 16 byte'ta
    if (binary_len < 16) {
        printf("UDP Encrypted Error: Data too short for IV\n");
        free(binary_data);
        return -1;
    }
    
    uint8_t* iv = binary_data;
    uint8_t* ciphertext = binary_data + 16;
    size_t ciphertext_len = binary_len - 16;
    
    char* decrypted_json = decrypt_data(ciphertext, ciphertext_len, CONFIG_DEFAULT_KEY, iv);
    free(binary_data);
    
    if (!decrypted_json) {
        printf("UDP Encrypted Error: Decryption failed\n");
        return -1;
    }
    
    printf("UDP: Data decrypted successfully\n");
    
    // Parse decrypted JSON
    tactical_data_t* tactical_data = parse_json_to_tactical_data(decrypted_json, filename);
    free(decrypted_json);
    
    if (tactical_data != NULL && tactical_data->is_valid) {
        printf("UDP: Encrypted tactical data parsed successfully\n");
        
        // Database'e kaydet
        char* response = db_save_tactical_data_and_get_response(tactical_data, filename);
        if (response) {
            printf("UDP: Database save response: %s\n", response);
            free(response);
        }
        
        free_tactical_data(tactical_data);
        
        printf("UDP Encrypted Success: Data saved to database for %s\n", filename);
        return 0;
    } else {
        printf("UDP Encrypted Error: Invalid decrypted tactical data format\n");
        if (tactical_data) free_tactical_data(tactical_data);
        return -1;
    }
}
