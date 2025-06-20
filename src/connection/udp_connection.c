/**
 * @file udp_connection.c
 * @brief UDP connectionless veri iletişimi ve ECDH session yönetimi
 * @ingroup udp_networking
 * 
 * UDP tabanlı tactical data iletişimi ve peer session management.
 * ECDH key exchange ve encrypted data processing desteği.
 */

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
#include "logger.h"

/// @brief Global UDP session listesi (linked list)
static udp_session_t* session_list = NULL;
/// @brief Session listesi için thread safety mutex
static pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;

/// @brief Session timeout süresi (5 dakika)
#define UDP_SESSION_TIMEOUT 300

/**
 * @brief UDP server'ı initialize eder
 * @param manager Connection manager
 * @return 0 başarı
 */
int udp_server_init(connection_manager_t* manager) {
    PRINTF_LOG("UDP Server modülü başlatılıyor...\n");
    
    manager->type = CONN_TYPE_UDP;
    manager->status = CONN_STATUS_STOPPED;
    manager->server_fd = -1;
    manager->is_active = false;
    manager->client_count = 0;
    manager->total_connections = 0;
    manager->total_requests = 0;
    
    strcpy(manager->name, "UDP Server");
    
    PRINTF_LOG("✓ UDP Server modülü hazır (Port: %d)\n", manager->port);
    return 0;
}

/**
 * @brief UDP server'ı başlatır ve datagram'ları dinlemeye başlar
 * @param manager Connection manager
 * @return 0 başarı, -1 hata
 */
int udp_server_start(connection_manager_t* manager) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    PRINTF_LOG("UDP Server başlatılıyor (Port: %d)...\n", manager->port);
    
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
    
    PRINTF_LOG("✓ UDP Server başarıyla başlatıldı (Port: %d)\n", manager->port);
    return 0;
}

/**
 * @brief UDP server'ı durdurur ve socket'ı kapatır
 * @param manager Connection manager
 * @return 0 başarı
 */
int udp_server_stop(connection_manager_t* manager) {
    if (manager->status != CONN_STATUS_RUNNING) {
        PRINTF_LOG("UDP Server zaten durdurulmuş\n");
        return 0;
    }
    
    PRINTF_LOG("UDP Server durduruluyor...\n");
    manager->status = CONN_STATUS_STOPPING;
    
    // Server socket'ını kapat
    if (manager->server_fd >= 0) {
        close(manager->server_fd);
        manager->server_fd = -1;
    }
    
    manager->status = CONN_STATUS_STOPPED;
    manager->is_active = false;
    
    PRINTF_LOG("✓ UDP Server durduruldu (Port: %d)\n", manager->port);
    return 0;
}

/**
 * @brief UDP server ana thread - datagram'ları alır ve işler
 * @param arg Connection manager pointer
 * @return NULL
 */
void* udp_server_thread(void* arg) {
    connection_manager_t* manager = (connection_manager_t*)arg;
    char buffer[CONFIG_BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    PRINTF_LOG("UDP Server thread başlatıldı (Port: %d)\n", manager->port);
    
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
        
        // Paketi işle
        buffer[bytes_received] = '\0';
        
        // ECDH anahtar değişimi mesajlarını kontrol et
        if (strncmp(buffer, "ECDH_", 5) == 0) {
            PRINTF_LOG("UDP: ECDH mesajı alındı: %s:%d\n", client_ip, client_port);
            if (udp_handle_key_exchange(manager->server_fd, &client_addr, buffer) == 0) {
                PRINTF_LOG("UDP: ECDH mesajı başarıyla işlendi\n");
            } else {
                PRINTF_LOG("UDP: ECDH mesajı işlenemedi\n");
                const char* error_response = "UDP_ERROR: ECDH failed";
                sendto(manager->server_fd, error_response, strlen(error_response), 0,
                       (struct sockaddr*)&client_addr, client_len);
            }
            // ECDH mesajları için connection sayısını artırma
            continue;
        }
        
        // Eski session'ları temizle (periyodik olarak)
        static time_t last_cleanup = 0;
        time_t current_time = time(NULL);
        if (current_time - last_cleanup > 60) { // Her dakika
            udp_cleanup_old_sessions();
            last_cleanup = current_time;
        }
        
        // JSON mesaj parsing (Tactical Data formatı)
        if (udp_parse_message(buffer, client_ip, client_port, manager) == 0) {
            // Sadece başarılı parse edilen gerçek veri mesajları için connection sayısını artır
            if (strncmp(buffer, "PARSE:", 6) == 0 || strncmp(buffer, "ENCRYPTED:", 10) == 0) {
                manager->total_connections++;
                increment_udp_connection();
            }
            
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
    
    PRINTF_LOG("UDP Server thread sonlandırıldı\n");
    return NULL;
}

/**
 * @brief UDP client socket oluşturur
 * @return Socket descriptor veya -1 hata
 */
int udp_client_init(void) {
    int client_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_socket < 0) {
        perror("UDP Client socket oluşturma hatası");
        return -1;
    }
    
    PRINTF_LOG("UDP Client socket oluşturuldu\n");
    return client_socket;
}

/**
 * @brief UDP datagram gönderir
 * @param socket UDP socket descriptor
 * @param hostname Hedef IP adresi
 * @param port Hedef port numarası
 * @param data Gönderilecek veri
 * @param length Veri boyutu
 * @return Gönderilen byte sayısı veya -1 hata
 */
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
    
    PRINTF_LOG("UDP Client veri gönderildi (%s:%d, %zd bytes)\n", hostname, port, bytes_sent);
    return bytes_sent;
}

/**
 * @brief UDP datagram alır ve gönderen bilgilerini döndürür
 * @param socket UDP socket descriptor
 * @param buffer Veri buffer'ı
 * @param buffer_size Buffer boyutu
 * @param sender_ip Gönderen IP adresi (output)
 * @param sender_port Gönderen port numarası (output)
 * @return Alınan byte sayısı veya -1 hata
 */
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
    
    PRINTF_LOG("UDP Client veri alındı (%zd bytes)\n", bytes_received);
    return bytes_received;
}

/**
 * @brief UDP client socket'ı kapatır
 * @param socket Socket descriptor
 */
void udp_client_close(int socket) {
    if (socket >= 0) {
        close(socket);
        PRINTF_LOG("UDP Client socket kapatıldı\n");
    }
}

/**
 * @brief UDP server packet istatistiklerini günceller
 * @param manager Connection manager
 * @param packet_received true: packet alındı
 */
void udp_update_stats(connection_manager_t* manager, bool packet_received) {
    if (packet_received) {
        manager->total_requests++;
        PRINTF_LOG("UDP Stats: Total packets=%d\n", manager->total_requests);
    }
}

/**
 * @brief UDP packet aktivitelerini loglar
 * @param client_ip Client IP adresi
 * @param client_port Client port numarası
 * @param packet_size Packet boyutu
 */
void udp_log_packet(const char* client_ip, int client_port, size_t packet_size) {
    time_t now = time(NULL);
    char* time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // newline'ı kaldır
    
    PRINTF_LOG("[%s] UDP PACKET: %s:%d (%zu bytes)\n", 
           time_str, client_ip, client_port, packet_size);
}

/**
 * @brief UDP protocol mesajlarını parse eder (PARSE/ENCRYPTED commands)
 * @param message Gelen mesaj
 * @param client_ip Client IP adresi
 * @param client_port Client port numarası
 * @param manager Connection manager
 * @return 0 başarı, -1 hata
 */
int udp_parse_message(const char* message, const char* client_ip, int client_port, connection_manager_t* manager) {
    PRINTF_LOG("UDP Mesaj parsing: %s (kaynak: %s:%d)\n", message, client_ip, client_port);
    
    // PING mesajı - basit test mesajı
    if (strcmp(message, "PING") == 0) {
        PRINTF_LOG("UDP: PING mesajı alındı - test bağlantısı\n");
        return 0; // Başarılı olarak dön
    }
    
    // Protokol mesajini parse et (PARSE:filename:content veya ENCRYPTED:filename:content)
    char *message_copy = strdup(message);
    if (!message_copy) {
        PRINTF_LOG("UDP Parse Error: Memory allocation failed\n");
        return -1;
    }
    
    char *command = strtok(message_copy, ":");
    char *filename = strtok(NULL, ":");
    char *content = strtok(NULL, "\0"); // Geri kalan kısmı al
    
    if (!command || !filename || !content) {
        PRINTF_LOG("UDP Parse Error: Invalid protocol format (Expected: COMMAND:filename:content)\n");
        free(message_copy);
        return -1;
    }
    
    PRINTF_LOG("UDP Command: %s, File: %s\n", command, filename);
    
    int result = -1;
    
    if (strcmp(command, "PARSE") == 0) {
        PRINTF_LOG("UDP Normal JSON parse ediliyor...\n");
        result = udp_process_json_data(content, filename, client_ip, client_port);
    } else if (strcmp(command, "ENCRYPTED") == 0) {
        PRINTF_LOG("UDP Encrypted JSON parse ediliyor...\n");
        
        // Session bul
        udp_session_t* session = udp_find_session(client_ip, client_port);
        if (session == NULL || !session->ecdh_initialized) {
            PRINTF_LOG("UDP Encrypted Error: ECDH session bulunamadı. Önce anahtar değişimi yapın.\n");
            result = -1;
        } else {
            result = udp_process_encrypted_data(content, filename, client_ip, client_port, session->ecdh_ctx.aes_key);
        }
    } else {
        PRINTF_LOG("UDP Parse Error: Unknown command: %s\n", command);
    }
    
    manager->total_requests++;
    free(message_copy);
    return result;
}

/**
 * @brief UDP JSON tactical data'yı işler ve database'e kaydeder
 * @param json_data JSON string
 * @param filename Dosya referansı
 * @param client_ip Client IP adresi
 * @param client_port Client port numarası
 * @return 0 başarı, -1 hata
 */
int udp_process_json_data(const char* json_data, const char* filename, const char* client_ip, int client_port) {
    PRINTF_LOG("UDP JSON Processing: %s from %s:%d\n", filename, client_ip, client_port);
    
    // JSON'u tactical data struct'ına parse et (TCP'deki gibi)
    tactical_data_t* tactical_data = parse_json_to_tactical_data(json_data, filename);
    if (tactical_data != NULL && tactical_data->is_valid) {
        PRINTF_LOG("UDP: Tactical data parsed successfully\n");
        
        // Database'e kaydet
        char* response = db_save_tactical_data_and_get_response(tactical_data, filename);
        if (response) {
            PRINTF_LOG("UDP: Database save response: %s\n", response);
            free(response);
        }
        
        free_tactical_data(tactical_data);
        
        PRINTF_LOG("UDP JSON Success: Data saved to database for %s\n", filename);
        return 0;
    } else {
        PRINTF_LOG("UDP JSON Error: Invalid tactical data format\n");
        if (tactical_data) free_tactical_data(tactical_data);
        return -1;
    }
}

/**
 * @brief ECDH session key ile şifrelenmiş UDP data'yı işler
 * @param encrypted_data Hex-encoded şifreli veri
 * @param filename Dosya referansı
 * @param client_ip Client IP adresi
 * @param client_port Client port numarası
 * @param session_key ECDH session anahtarı
 * @return 0 başarı, -1 hata
 */
int udp_process_encrypted_data(const char* encrypted_data, const char* filename, const char* client_ip, int client_port, const uint8_t* session_key) {
    PRINTF_LOG("UDP Encrypted Processing: %s from %s:%d\n", filename, client_ip, client_port);
    
    if (session_key == NULL) {
        PRINTF_LOG("UDP Encrypted Error: Session key NULL - anahtar değişimi yapılmamış\n");
        return -1;
    }
    
    // Hex data'yı decode et - standart crypto_utils fonksiyonunu kullan
    size_t binary_len;
    uint8_t* binary_data = hex_to_bytes(encrypted_data, &binary_len);
    if (!binary_data) {
        PRINTF_LOG("UDP Encrypted Error: Hex decode failed\n");
        return -1;
    }
    
    // Decrypt data - IV ilk 16 byte'ta
    if (binary_len < 16) {
        PRINTF_LOG("UDP Encrypted Error: Data too short for IV\n");
        free(binary_data);
        return -1;
    }
    
    uint8_t* iv = binary_data;
    uint8_t* ciphertext = binary_data + 16;
    size_t ciphertext_len = binary_len - 16;
    
    char* decrypted_json = decrypt_data(ciphertext, ciphertext_len, session_key, iv);
    free(binary_data);
    
    if (!decrypted_json) {
        PRINTF_LOG("UDP Encrypted Error: Decryption failed\n");
        return -1;
    }
    
    PRINTF_LOG("UDP: Data decrypted successfully\n");
    
    // Parse decrypted JSON
    tactical_data_t* tactical_data = parse_json_to_tactical_data(decrypted_json, filename);
    free(decrypted_json);
    
    if (tactical_data != NULL && tactical_data->is_valid) {
        PRINTF_LOG("UDP: Encrypted tactical data parsed successfully\n");
        
        // Database'e kaydet
        char* response = db_save_tactical_data_and_get_response(tactical_data, filename);
        if (response) {
            PRINTF_LOG("UDP: Database save response: %s\n", response);
            free(response);
        }
        
        free_tactical_data(tactical_data);
        
        PRINTF_LOG("UDP Encrypted Success: Data saved to database for %s\n", filename);
        return 0;
    } else {
        PRINTF_LOG("UDP Encrypted Error: Invalid decrypted tactical data format\n");
        if (tactical_data) free_tactical_data(tactical_data);
        return -1;
    }
}

/**
 * @brief Client IP:port için UDP session bulur
 * @param client_ip Client IP adresi
 * @param client_port Client port numarası
 * @return Session pointer veya NULL
 */
udp_session_t* udp_find_session(const char* client_ip, int client_port) {
    pthread_mutex_lock(&session_mutex);
    
    udp_session_t* current = session_list;
    while (current != NULL) {
        if (strcmp(current->client_ip, client_ip) == 0 && current->client_port == client_port) {
            current->last_activity = time(NULL);
            pthread_mutex_unlock(&session_mutex);
            return current;
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&session_mutex);
    return NULL;
}

/**
 * @brief Yeni UDP session oluşturur ve ECDH initialize eder
 * @param client_ip Client IP adresi
 * @param client_port Client port numarası
 * @return Session pointer veya NULL hata durumunda
 */
udp_session_t* udp_create_session(const char* client_ip, int client_port) {
    udp_session_t* session = malloc(sizeof(udp_session_t));
    if (session == NULL) {
        return NULL;
    }
    
    memset(session, 0, sizeof(udp_session_t));
    strncpy(session->client_ip, client_ip, INET_ADDRSTRLEN - 1);
    session->client_port = client_port;
    session->last_activity = time(NULL);
    session->ecdh_initialized = false;
    session->next = NULL;
    
    // ECDH context'i başlat
    if (!ecdh_init_context(&session->ecdh_ctx)) {
        free(session);
        return NULL;
    }
    
    // Anahtar çifti üret
    if (!ecdh_generate_keypair(&session->ecdh_ctx)) {
        ecdh_cleanup_context(&session->ecdh_ctx);
        free(session);
        return NULL;
    }
    
    session->ecdh_initialized = true;
    
    // Session listesine ekle
    pthread_mutex_lock(&session_mutex);
    session->next = session_list;
    session_list = session;
    pthread_mutex_unlock(&session_mutex);
    
    PRINTF_LOG("UDP: Yeni session oluşturuldu: %s:%d\n", client_ip, client_port);
    return session;
}

/**
 * @brief UDP session'ı temizler ve listeden çıkarır
 * @param session Temizlenecek session
 */
void udp_cleanup_session(udp_session_t* session) {
    if (session == NULL) {
        return;
    }
    
    pthread_mutex_lock(&session_mutex);
    
    // Session'ı listeden çıkar
    if (session_list == session) {
        session_list = session->next;
    } else {
        udp_session_t* current = session_list;
        while (current != NULL && current->next != session) {
            current = current->next;
        }
        if (current != NULL) {
            current->next = session->next;
        }
    }
    
    pthread_mutex_unlock(&session_mutex);
    
    // ECDH temizle
    if (session->ecdh_initialized) {
        ecdh_cleanup_context(&session->ecdh_ctx);
    }
    
    PRINTF_LOG("UDP: Session temizlendi: %s:%d\n", session->client_ip, session->client_port);
    free(session);
}

/**
 * @brief Timeout olan eski UDP session'larını temizler
 */
void udp_cleanup_old_sessions(void) {
    time_t current_time = time(NULL);
    
    pthread_mutex_lock(&session_mutex);
    
    udp_session_t* current = session_list;
    udp_session_t* prev = NULL;
    
    while (current != NULL) {
        if (current_time - current->last_activity > UDP_SESSION_TIMEOUT) {
            udp_session_t* to_remove = current;
            
            if (prev == NULL) {
                session_list = current->next;
            } else {
                prev->next = current->next;
            }
            
            current = current->next;
            
            pthread_mutex_unlock(&session_mutex);
            udp_cleanup_session(to_remove);
            pthread_mutex_lock(&session_mutex);
        } else {
            prev = current;
            current = current->next;
        }
    }
    
    pthread_mutex_unlock(&session_mutex);
}

/**
 * @brief UDP ECDH key exchange mesajlarını işler
 * @param socket UDP socket descriptor
 * @param client_addr Client address bilgileri
 * @param message ECDH mesajı (ECDH_INIT/ECDH_PUB)
 * @return 0 başarı, -1 hata
 */
int udp_handle_key_exchange(int socket, struct sockaddr_in* client_addr, const char* message) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr->sin_port);
    
    if (strncmp(message, "ECDH_INIT", 9) == 0) {
        PRINTF_LOG("UDP: ECDH init isteği alındı: %s:%d\n", client_ip, client_port);
        
        // Mevcut session'ı bul veya yeni oluştur
        udp_session_t* session = udp_find_session(client_ip, client_port);
        if (session == NULL) {
            session = udp_create_session(client_ip, client_port);
            if (session == NULL) {
                PRINTF_LOG("UDP: Session oluşturulamadı\n");
                return -1;
            }
        }
        
        // Public key'i gönder
        char response[ECC_PUB_KEY_SIZE * 2 + 20]; // Hex encoded + prefix
        strcpy(response, "ECDH_PUB:");
        char* hex_key = bytes_to_hex(session->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE);
        if (hex_key) {
            strcat(response, hex_key);
            free(hex_key);
        }
        
        ssize_t sent = sendto(socket, response, strlen(response), 0,
                             (struct sockaddr*)client_addr, sizeof(*client_addr));
        if (sent < 0) {
            PRINTF_LOG("UDP: Public key gönderilemedi\n");
            return -1;
        }
        
        PRINTF_LOG("UDP: Public key gönderildi: %s:%d\n", client_ip, client_port);
        return 0;
    }
    else if (strncmp(message, "ECDH_PUB:", 9) == 0) {
        PRINTF_LOG("UDP: Client public key alındı: %s:%d\n", client_ip, client_port);
        
        udp_session_t* session = udp_find_session(client_ip, client_port);
        if (session == NULL) {
            PRINTF_LOG("UDP: Session bulunamadı\n");
            return -1;
        }
        
        // Client'ın public key'ini decode et
        size_t peer_key_len;
        uint8_t* peer_public_key = hex_to_bytes(message + 9, &peer_key_len);
        if (peer_public_key == NULL || peer_key_len != ECC_PUB_KEY_SIZE) {
            PRINTF_LOG("UDP: Geçersiz public key\n");
            if (peer_public_key) free(peer_public_key);
            return -1;
        }
        
        // Shared secret hesapla
        if (!ecdh_compute_shared_secret(&session->ecdh_ctx, peer_public_key)) {
            PRINTF_LOG("UDP: Shared secret hesaplanamadı\n");
            free(peer_public_key);
            return -1;
        }
        
        // AES anahtarını türet
        if (!ecdh_derive_aes_key(&session->ecdh_ctx)) {
            PRINTF_LOG("UDP: AES anahtarı türetilemedi\n");
            free(peer_public_key);
            return -1;
        }
        
        free(peer_public_key);
        
        // Onay mesajı gönder
        const char* ack = "ECDH_OK";
        sendto(socket, ack, strlen(ack), 0,
               (struct sockaddr*)client_addr, sizeof(*client_addr));
        
        PRINTF_LOG("UDP: ✓ ECDH anahtar değişimi tamamlandı: %s:%d\n", client_ip, client_port);
        return 0;
    }
    
    return -1;
}
