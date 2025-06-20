/**
 * @file p2p_connection.c
 * @brief Peer-to-peer network bağlantı yönetimi ve ECDH güvenli iletişim
 * @ingroup p2p_networking
 * 
 * P2P node management, mesh network, tactical data distribution.
 * ECDH key exchange ve encrypted peer communication desteği.
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
#include <cjson/cJSON.h>
#include "p2p_connection.h"
#include "config.h"
#include "thread_monitor.h"
#include "crypto_utils.h"
#include "database.h"
#include "json_utils.h"
#include "logger.h"

/// @brief Aktif peer bilgilerini tutan global array
static p2p_peer_t peers[CONFIG_MAX_CLIENTS];
/// @brief Mevcut connected peer sayısı
static int peer_count = 0;
/// @brief P2P işlemlerini korumak için mutex
static pthread_mutex_t p2p_mutex = PTHREAD_MUTEX_INITIALIZER;
/// @brief Local P2P node'unun benzersiz kimliği
static char local_node_id[128];

/// @brief Peer handler thread parametreleri
typedef struct {
    int socket;                    ///< Peer socket file descriptor
    connection_manager_t* manager; ///< Connection manager context
} peer_handler_params_t;

/**
 * @brief P2P node'unu initialize eder ve peer management hazırlar
 * @param manager P2P node connection manager
 * @return 0 başarı
 */
int p2p_node_init(connection_manager_t* manager) {
    PRINTF_LOG("P2P Node modülü başlatılıyor...\n");
    
    manager->type = CONN_TYPE_P2P;
    manager->status = CONN_STATUS_STOPPED;
    manager->server_fd = -1;
    manager->is_active = false;
    manager->client_count = 0;
    manager->total_connections = 0;
    manager->total_requests = 0;
    
    strcpy(manager->name, "P2P Node");
    
    // Benzersiz node ID oluştur
    snprintf(local_node_id, sizeof(local_node_id), "NODE_%d_%ld", 
             manager->port, (long)time(NULL));
    
    // Peer listesini temizle
    pthread_mutex_lock(&p2p_mutex);
    memset(peers, 0, sizeof(peers));
    peer_count = 0;
    pthread_mutex_unlock(&p2p_mutex);
    
    PRINTF_LOG("✓ P2P Node modülü hazır (Port: %d, NodeID: %s)\n", 
           manager->port, local_node_id);
    return 0;
}

/**
 * @brief P2P node'unu başlatır ve peer connections kabul eder
 * @param manager P2P node connection manager
 * @return 0 başarı, -1 hata
 */
int p2p_node_start(connection_manager_t* manager) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    PRINTF_LOG("P2P Node başlatılıyor (Port: %d)...\n", manager->port);
    
    // Socket oluştur (TCP tabanlı P2P)
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("P2P Socket oluşturma hatası");
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    // Socket seçenekleri
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("P2P setsockopt hatası");
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
        perror("P2P Bind hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    // Dinlemeye başla
    if (listen(server_fd, CONFIG_MAX_CLIENTS) < 0) {
        perror("P2P Listen hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    manager->server_fd = server_fd;
    manager->status = CONN_STATUS_RUNNING;
    manager->is_active = true;
    
    // Server thread'ini başlat
    if (pthread_create(&manager->server_thread, NULL, p2p_node_thread, manager) != 0) {
        perror("P2P Thread oluşturma hatası");
        close(server_fd);
        manager->status = CONN_STATUS_ERROR;
        return -1;
    }
    
    pthread_detach(manager->server_thread);
    
    PRINTF_LOG("✓ P2P Node başarıyla başlatıldı (Port: %d, NodeID: %s)\n", 
           manager->port, local_node_id);
    return 0;
}

/**
 * @brief P2P node'unu durdurur ve tüm peer bağlantılarını kapatır
 * @param manager P2P node connection manager
 * @return 0 başarı
 */
int p2p_node_stop(connection_manager_t* manager) {
    if (manager->status != CONN_STATUS_RUNNING) {
        PRINTF_LOG("P2P Node zaten durdurulmuş\n");
        return 0;
    }
    
    PRINTF_LOG("P2P Node durduruluyor...\n");
    manager->status = CONN_STATUS_STOPPING;
    
    // Tüm peer bağlantılarını kapat
    pthread_mutex_lock(&p2p_mutex);
    for (int i = 0; i < peer_count; i++) {
        if (peers[i].is_connected && peers[i].socket_fd >= 0) {
            close(peers[i].socket_fd);
            peers[i].is_connected = false;
        }
    }
    peer_count = 0;
    pthread_mutex_unlock(&p2p_mutex);
    
    // Server socket'ını kapat
    if (manager->server_fd >= 0) {
        close(manager->server_fd);
        manager->server_fd = -1;
    }
    
    manager->status = CONN_STATUS_STOPPED;
    manager->is_active = false;
    
    PRINTF_LOG("✓ P2P Node durduruldu (Port: %d)\n", manager->port);
    return 0;
}

/**
 * @brief P2P node ana thread - incoming peer connections kabul eder
 * @param arg Connection manager pointer
 * @return NULL
 */
void* p2p_node_thread(void* arg) {
    connection_manager_t* manager = (connection_manager_t*)arg;
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    
    PRINTF_LOG("P2P Node thread başlatıldı (Port: %d, NodeID: %s)\n", 
           manager->port, local_node_id);
    
    while (manager->is_active && manager->status == CONN_STATUS_RUNNING) {
        int peer_socket = accept(manager->server_fd, (struct sockaddr*)&peer_addr, &peer_len);
        
        if (peer_socket < 0) {
            if (manager->is_active) {
                perror("P2P Accept hatası");
            }
            continue;
        }
        
        // Peer IP'sini al
        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, INET_ADDRSTRLEN);
        int peer_port = ntohs(peer_addr.sin_port);
        
        PRINTF_LOG("P2P Yeni peer bağlantısı: %s:%d\n", peer_ip, peer_port);
        
        // Peer'i listeye ekle
        pthread_mutex_lock(&p2p_mutex);
        if (peer_count < CONFIG_MAX_CLIENTS) {
            strcpy(peers[peer_count].ip, peer_ip);
            peers[peer_count].port = peer_port;
            snprintf(peers[peer_count].node_id, sizeof(peers[peer_count].node_id), 
                    "PEER_%s_%d_%ld", peer_ip, peer_port, (long)time(NULL));
            peers[peer_count].last_seen = time(NULL);
            peers[peer_count].is_connected = true;
            peers[peer_count].socket_fd = peer_socket;
            peer_count++;
            
            p2p_log_peer_activity(peers[peer_count-1].node_id, "CONNECTED");
        } else {
            PRINTF_LOG("P2P Maksimum peer sayısına ulaşıldı, bağlantı reddediliyor\n");
            close(peer_socket);
        }
        pthread_mutex_unlock(&p2p_mutex);
        
        // İstatistikleri güncelle
        p2p_update_stats(manager);
        
        // Peer message handler'ı başlat
        pthread_t peer_handler_thread;
        
        // Thread parametreleri için struct oluştur
        peer_handler_params_t* params = malloc(sizeof(peer_handler_params_t));
        params->socket = peer_socket;
        params->manager = manager;
        
        if (pthread_create(&peer_handler_thread, NULL, 
                          p2p_peer_thread_wrapper, params) != 0) {
            perror("P2P Peer handler thread oluşturma hatası");
            close(peer_socket);
            free(params);
        } else {
            pthread_detach(peer_handler_thread);
        }
    }
    
    PRINTF_LOG("P2P Node thread sonlandırıldı\n");
    return NULL;
}

/**
 * @brief P2P network'e manuel peer ekler
 * @param ip Peer IP adresi
 * @param port Peer port numarası
 * @return 0 başarı, -1 hata
 */
int p2p_add_peer(const char* ip, int port) {
    pthread_mutex_lock(&p2p_mutex);
    
    if (peer_count >= CONFIG_MAX_CLIENTS) {
        pthread_mutex_unlock(&p2p_mutex);
        PRINTF_LOG("P2P Maksimum peer sayısına ulaşıldı\n");
        return -1;
    }
    
    // Zaten var mı kontrol et
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].ip, ip) == 0 && peers[i].port == port) {
            pthread_mutex_unlock(&p2p_mutex);
            PRINTF_LOG("P2P Peer zaten mevcut: %s:%d\n", ip, port);
            return 0;
        }
    }
    
    // Yeni peer ekle
    strcpy(peers[peer_count].ip, ip);
    peers[peer_count].port = port;
    snprintf(peers[peer_count].node_id, sizeof(peers[peer_count].node_id), 
            "PEER_%s_%d_%ld", ip, port, (long)time(NULL));
    peers[peer_count].last_seen = time(NULL);
    peers[peer_count].is_connected = false;
    peers[peer_count].socket_fd = -1;
    peer_count++;
    
    PRINTF_LOG("P2P Yeni peer eklendi: %s:%d (NodeID: %s)\n", 
           ip, port, peers[peer_count-1].node_id);
    
    pthread_mutex_unlock(&p2p_mutex);
    return 0;
}

/**
 * @brief Peer'i P2P network'ten kaldırır
 * @param node_id Kaldırılacak peer'in node ID'si
 * @return 0 başarı, -1 bulunamadı
 */
int p2p_remove_peer(const char* node_id) {
    pthread_mutex_lock(&p2p_mutex);
    
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].node_id, node_id) == 0) {
            // Bağlantı varsa kapat
            if (peers[i].is_connected && peers[i].socket_fd >= 0) {
                close(peers[i].socket_fd);
            }
            
            // Array'den çıkar
            for (int j = i; j < peer_count - 1; j++) {
                peers[j] = peers[j + 1];
            }
            peer_count--;
            
            PRINTF_LOG("P2P Peer kaldırıldı: %s\n", node_id);
            p2p_log_peer_activity(node_id, "REMOVED");
            
            pthread_mutex_unlock(&p2p_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&p2p_mutex);
    PRINTF_LOG("P2P Peer bulunamadı: %s\n", node_id);
    return -1;
}

/**
 * @brief Peer'e TCP bağlantısı kurar
 * @param peer Bağlanılacak peer
 * @return 0 başarı, -1 hata
 */
int p2p_connect_to_peer(p2p_peer_t* peer) {
    if (peer->is_connected) {
        PRINTF_LOG("P2P Peer zaten bağlı: %s:%d\n", peer->ip, peer->port);
        return 0;
    }
    
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("P2P Peer socket oluşturma hatası");
        return -1;
    }
    
    struct sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer->port);
    inet_pton(AF_INET, peer->ip, &peer_addr.sin_addr);
    
    if (connect(socket_fd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("P2P Peer bağlantı hatası");
        close(socket_fd);
        return -1;
    }
    
    peer->socket_fd = socket_fd;
    peer->is_connected = true;
    peer->last_seen = time(NULL);
    
    PRINTF_LOG("P2P Peer'e bağlandı: %s:%d\n", peer->ip, peer->port);
    p2p_log_peer_activity(peer->node_id, "CONNECTED");
    
    return 0;
}

/**
 * @brief Peer bağlantısını kapatır
 * @param peer Bağlantısı kesilecek peer
 * @return 0 başarı
 */
int p2p_disconnect_from_peer(p2p_peer_t* peer) {
    if (!peer->is_connected) {
        return 0;
    }
    
    if (peer->socket_fd >= 0) {
        close(peer->socket_fd);
        peer->socket_fd = -1;
    }
    
    peer->is_connected = false;
    
    PRINTF_LOG("P2P Peer bağlantısı kesildi: %s:%d\n", peer->ip, peer->port);
    p2p_log_peer_activity(peer->node_id, "DISCONNECTED");
    
    return 0;
}

/**
 * @brief Peer mesajlarını işler ve ECDH protokolünü yönetir
 * @param socket Peer socket descriptor
 * @param manager Connection manager
 */
void p2p_handle_peer_message(int socket, connection_manager_t* manager) {
    char buffer[CONFIG_BUFFER_SIZE];
    
    // P2P peer için ECDH anahtar değişimi yap
    PRINTF_LOG("P2P: Yeni peer ile ECDH anahtar değişimi başlıyor...\n");
    
    // Yeni peer oluştur ve ECDH başlat
    p2p_peer_t temp_peer;
    memset(&temp_peer, 0, sizeof(p2p_peer_t));
    temp_peer.socket_fd = socket;
    snprintf(temp_peer.node_id, sizeof(temp_peer.node_id), "PEER_SOCKET_%d", socket);
    
    if (!p2p_init_ecdh_for_peer(&temp_peer)) {
        PRINTF_LOG("P2P: ECDH başlatılamadı\n");
        close(socket);
        return;
    }
    
    // ECDH anahtar değişimi yap
    if (!p2p_exchange_keys_with_peer(&temp_peer)) {
        PRINTF_LOG("P2P: Anahtar değişimi başarısız\n");
        p2p_cleanup_ecdh_for_peer(&temp_peer);
        close(socket);
        return;
    }
    
    PRINTF_LOG("P2P: ECDH anahtar değişimi tamamlandı\n");
    
    while (1) {
        memset(buffer, 0, CONFIG_BUFFER_SIZE);
        
        ssize_t bytes_received = recv(socket, buffer, CONFIG_BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            PRINTF_LOG("P2P Peer bağlantısı kesildi (socket: %d)\n", socket);
            break;
        }
        
        buffer[bytes_received] = '\0';
        PRINTF_LOG("P2P Mesaj alındı (%zd bytes): %.100s%s\n", 
               bytes_received, buffer, bytes_received > 100 ? "..." : "");
        
        // P2P mesajını işle
        if (strncmp(buffer, "P2P_DATA:", 9) == 0) {
            // Tactical data mesajı
            char* data_part = buffer + 9;
            PRINTF_LOG("P2P Tactical data işleniyor...\n");
            
            // P2P protokol formatını parse et
            if (process_p2p_tactical_data(data_part) == 0) {
                const char* response = "P2P_ACK:Data processed successfully";
                send(socket, response, strlen(response), 0);
                PRINTF_LOG("P2P Tactical data başarıyla işlendi\n");
            } else {
                const char* response = "P2P_NACK:Data processing failed";
                send(socket, response, strlen(response), 0);
                PRINTF_LOG("P2P Tactical data işleme hatası\n");
            }
        } else if (strncmp(buffer, "P2P_ENCRYPTED:", 14) == 0) {
            // Şifreli tactical data mesajı
            char* encrypted_part = buffer + 14;
            PRINTF_LOG("P2P Şifreli tactical data işleniyor...\n");
            
            // ENCRYPTED:filename:hexdata formatını parse et
            if (strncmp(encrypted_part, "ENCRYPTED:", 10) == 0) {
                char* data_start = encrypted_part + 10;
                
                // Filename ve hex data'yı ayır
                char* first_colon = strchr(data_start, ':');
                if (first_colon != NULL) {
                    size_t filename_len = first_colon - data_start;
                    char filename[256];
                    strncpy(filename, data_start, filename_len);
                    filename[filename_len] = '\0';
                    
                    char* hex_data = first_colon + 1;
                    
                    PRINTF_LOG("P2P: Parsing - File: %s, Hex length: %zu\n", filename, strlen(hex_data));
                    
                    // Şifreli veriyi işle
                    if (p2p_process_encrypted_data(hex_data, filename, &temp_peer) == 0) {
                        const char* response = "P2P_ACK:Encrypted data processed successfully";
                        send(socket, response, strlen(response), 0);
                        PRINTF_LOG("P2P Şifreli tactical data başarıyla işlendi\n");
                    } else {
                        const char* response = "P2P_NACK:Encrypted data processing failed";
                        send(socket, response, strlen(response), 0);
                        PRINTF_LOG("P2P Şifreli tactical data işleme hatası\n");
                    }
                } else {
                    PRINTF_LOG("P2P: Geçersiz şifreli veri formatı - colon bulunamadı\n");
                    const char* response = "P2P_NACK:Invalid encrypted data format";
                    send(socket, response, strlen(response), 0);
                }
            } else {
                PRINTF_LOG("P2P: Geçersiz şifreli veri formatı - ENCRYPTED prefix yok\n");
                const char* response = "P2P_NACK:Invalid encrypted data format";
                send(socket, response, strlen(response), 0);
            }
        } else {
            // Echo response for other messages
            char response[CONFIG_BUFFER_SIZE];
            size_t max_data_len = CONFIG_BUFFER_SIZE - 10 - 1; // "P2P_ECHO:" + null terminator
            size_t buffer_len = strlen(buffer);
            
            // Buffer'ı güvenli boyutta truncate et
            if (buffer_len > max_data_len) {
                buffer[max_data_len] = '\0';
                buffer_len = max_data_len;
            }
            
            // Güvenli snprintf ile response oluştur
            int written = snprintf(response, sizeof(response), "P2P_ECHO:%.*s", 
                                  (int)buffer_len, buffer);
            if (written > 0 && written < (int)sizeof(response)) {
                send(socket, response, written, 0);
            } else {
                // Fallback: basit response
                const char* simple_response = "P2P_ECHO:DATA_TOO_LARGE";
                send(socket, simple_response, strlen(simple_response), 0);
            }
        }
        
        if (manager) {
            manager->total_requests++;
        }
    }
    
    // ECDH temizliği
    p2p_cleanup_ecdh_for_peer(&temp_peer);
    
    close(socket);
}

/**
 * @brief Tüm bağlı peer'lere mesaj broadcast eder
 * @param message Broadcast edilecek mesaj
 * @return Mesajın gönderildiği peer sayısı
 */
int p2p_broadcast_message(const char* message) {
    int sent_count = 0;
    
    pthread_mutex_lock(&p2p_mutex);
    
    for (int i = 0; i < peer_count; i++) {
        if (peers[i].is_connected && peers[i].socket_fd >= 0) {
            if (send(peers[i].socket_fd, message, strlen(message), 0) > 0) {
                sent_count++;
                PRINTF_LOG("P2P Broadcast gönderildi: %s -> %s\n", 
                       message, peers[i].node_id);
            }
        }
    }
    
    pthread_mutex_unlock(&p2p_mutex);
    
    PRINTF_LOG("P2P Broadcast tamamlandı: %d peer'e gönderildi\n", sent_count);
    return sent_count;
}

/**
 * @brief P2P node istatistiklerini günceller
 * @param manager Connection manager
 */
void p2p_update_stats(connection_manager_t* manager) {
    manager->client_count = peer_count;
    PRINTF_LOG("P2P Stats: Connected peers=%d, Total requests=%d\n", 
           manager->client_count, manager->total_requests);
}

/**
 * @brief Peer aktivitelerini timestamp ile loglar
 * @param node_id Peer node ID'si
 * @param activity Aktivite türü
 */
void p2p_log_peer_activity(const char* node_id, const char* activity) {
    time_t now = time(NULL);
    char* time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // newline'ı kaldır
    
    PRINTF_LOG("[%s] P2P %s: %s\n", time_str, activity, node_id);
}

/**
 * @brief Mevcut peer sayısını döndürür
 * @return Bağlı peer sayısı
 * @ingroup p2p_networking
 */
int p2p_get_peer_count(void) {
    pthread_mutex_lock(&p2p_mutex);
    int count = peer_count;
    pthread_mutex_unlock(&p2p_mutex);
    return count;
}

/**
 * @brief Tüm peer listesini ekrana yazdırır
 * @ingroup p2p_networking
 */
void p2p_list_peers(void) {
    pthread_mutex_lock(&p2p_mutex);
    
    PRINTF_LOG("\n=== P2P PEER LIST ===\n");
    PRINTF_LOG("Local Node ID: %s\n", local_node_id);
    PRINTF_LOG("Connected Peers: %d\n", peer_count);
    
    for (int i = 0; i < peer_count; i++) {
        PRINTF_LOG("  [%d] %s:%d (%s) - %s\n", 
               i + 1,
               peers[i].ip, 
               peers[i].port,
               peers[i].node_id,
               peers[i].is_connected ? "CONNECTED" : "DISCONNECTED");
    }
    
    PRINTF_LOG("====================\n\n");
    
    pthread_mutex_unlock(&p2p_mutex);
}

/**
 * @brief P2P tactical data işler (şifreli/normal)
 * @param data İşlenecek JSON data
 * @return 0 başarı, -1 hata
 * @ingroup p2p_networking
 */
int process_tactical_data(const char* data) {
    if (data == NULL || strlen(data) == 0) {
        PRINTF_LOG("P2P Boş data alındı\n");
        return -1;
    }
    
    tactical_data_t* tactical_data = NULL;
    
    // Eğer hex format ise decrypt et
    if (strstr(data, "\"encrypted_data\":") != NULL) {
        PRINTF_LOG("P2P Şifreli data decrypt ediliyor...\n");
        
        // JSON parse ederek encrypted_data değerini al
        cJSON* json = cJSON_Parse(data);
        if (!json) {
            PRINTF_LOG("P2P Error: JSON parse failed\n");
            return -1;
        }
        
        cJSON* encrypted_data_obj = cJSON_GetObjectItem(json, "encrypted_data");
        if (!encrypted_data_obj || !cJSON_IsString(encrypted_data_obj)) {
            PRINTF_LOG("P2P Error: encrypted_data field not found\n");
            cJSON_Delete(json);
            return -1;
        }
        
        const char* encrypted_hex = cJSON_GetStringValue(encrypted_data_obj);
        
        // Hex data'yı decode et
        size_t binary_len;
        uint8_t* binary_data = hex_to_bytes(encrypted_hex, &binary_len);
        cJSON_Delete(json);
        
        if (!binary_data) {
            PRINTF_LOG("P2P Encrypted Error: Hex decode failed\n");
            return -1;
        }
        
        // Decrypt data - IV ilk 16 byte'ta
        if (binary_len < 16) {
            PRINTF_LOG("P2P Encrypted Error: Data too short for IV\n");
            free(binary_data);
            return -1;
        }
        
        uint8_t* iv = binary_data;
        uint8_t* ciphertext = binary_data + 16;
        size_t ciphertext_len = binary_len - 16;
        
        char* decrypted_json = decrypt_data(ciphertext, ciphertext_len, NULL, iv);
        free(binary_data);
        
        if (!decrypted_json) {
            PRINTF_LOG("P2P Encrypted Error: Decryption failed - P2P şu anda ECDH desteklemiyor\n");
            PRINTF_LOG("P2P Encrypted Info: TCP bağlantısı kullanarak ECDH ile şifreli iletişim yapın\n");
            return -1;
        }
        
        PRINTF_LOG("P2P: Data decrypted successfully\n");
        
        // Şifrelenmiş JSON'u çöz
        tactical_data = parse_json_to_tactical_data(decrypted_json, "p2p_data");
        free(decrypted_json);
    } else {
        PRINTF_LOG("P2P Normal data processing\n");
        // Normal JSON processing
        tactical_data = parse_json_to_tactical_data(data, "p2p_data");
    }
    
    if (tactical_data != NULL && tactical_data->is_valid) {
        PRINTF_LOG("P2P: Tactical data parsed successfully\n");
        
        // Database'e kaydet
        char* response = db_save_tactical_data_and_get_response(tactical_data, "p2p_data");
        if (response) {
            PRINTF_LOG("P2P: Database save response: %s\n", response);
            free(response);
        }
        
        free_tactical_data(tactical_data);
        
        PRINTF_LOG("P2P Success: Data saved to database\n");
        return 0;
    } else {
        PRINTF_LOG("P2P Error: Invalid tactical data format\n");
        if (tactical_data) free_tactical_data(tactical_data);
        return -1;
    }
}

/**
 * @brief P2P protokol formatında data işler
 * @param p2p_data CLIENT_ID:TYPE:FILENAME:DATA formatında veri
 * @return 0 başarı, -1 hata
 * @ingroup p2p_networking
 */
int process_p2p_tactical_data(const char* p2p_data) {
    if (p2p_data == NULL || strlen(p2p_data) == 0) {
        PRINTF_LOG("P2P Boş protocol data alındı\n");
        return -1;
    }
    
    PRINTF_LOG("P2P Protocol data: %.100s%s\n", p2p_data, strlen(p2p_data) > 100 ? "..." : "");
    
    // P2P formatını parse et: CLIENT_ID:TYPE:FILENAME:DATA
    size_t data_len = strlen(p2p_data);
    char* data_copy = malloc(data_len + 1);
    if (!data_copy) {
        PRINTF_LOG("P2P Memory allocation failed\n");
        return -1;
    }
    strcpy(data_copy, p2p_data);
    
    char* client_id = strtok(data_copy, ":");
    char* data_type = strtok(NULL, ":");
    char* filename = strtok(NULL, ":");
    char* json_data = strtok(NULL, "");  // Rest of the string
    
    if (!client_id || !data_type || !filename || !json_data) {
        PRINTF_LOG("P2P Invalid protocol format\n");
        free(data_copy);
        return -1;
    }
    
    PRINTF_LOG("P2P Parse: Client=%s, Type=%s, File=%s\n", client_id, data_type, filename);
    
    int result = -1;
    
    if (strcmp(data_type, "ENCRYPTED") == 0) {
        PRINTF_LOG("P2P Encrypted data processing\n");
        // Encrypted data için JSON wrapper oluştur
        cJSON* wrapper = cJSON_CreateObject();
        cJSON_AddStringToObject(wrapper, "encrypted_data", json_data);
        
        char* wrapper_str = cJSON_Print(wrapper);
        cJSON_Delete(wrapper);
        
        if (wrapper_str) {
            result = process_tactical_data(wrapper_str);
            free(wrapper_str);
        }
    } else if (strcmp(data_type, "NORMAL") == 0) {
        PRINTF_LOG("P2P Normal data processing\n");
        // Normal JSON data
        result = process_tactical_data(json_data);
    } else {
        PRINTF_LOG("P2P Unknown data type: %s\n", data_type);
    }
    
    free(data_copy);
    return result;
}

/**
 * @brief Peer'e keepalive mesajı gönderir
 * @param peer Keepalive gönderilecek peer
 * @return 0 başarı, -1 hata
 * @ingroup p2p_networking
 */
int p2p_send_keepalive(p2p_peer_t* peer) {
    if (peer && peer->is_connected) {
        const char* keepalive_msg = "P2P_KEEPALIVE";
        send(peer->socket_fd, keepalive_msg, strlen(keepalive_msg), 0);
        peer->last_seen = time(NULL);
        return 0;
    }
    return -1;
}

/**
 * @brief Tüm peer bağlantılarının durumunu kontrol eder
 * @ingroup p2p_networking
 */
void p2p_maintain_connections(void) {
    // Basit keepalive implementasyonu
    pthread_mutex_lock(&p2p_mutex);
    for (int i = 0; i < peer_count; i++) {
        if (peers[i].is_connected) {
            p2p_send_keepalive(&peers[i]);
        }
    }
    pthread_mutex_unlock(&p2p_mutex);
}

/**
 * @brief Peer handler thread wrapper fonksiyonu
 * @param arg peer_handler_params_t yapısı
 * @return NULL
 * @ingroup p2p_networking
 */
void* p2p_peer_thread_wrapper(void* arg) {
    peer_handler_params_t* params = (peer_handler_params_t*)arg;
    
    p2p_handle_peer_message(params->socket, params->manager);
    
    free(params);
    return NULL;
}

/**
 * @brief Peer için ECDH anahtar değişimi başlatır
 * @param peer ECDH başlatılacak peer
 * @return 1 başarı, 0 hata
 * @ingroup p2p_networking
 */
int p2p_init_ecdh_for_peer(p2p_peer_t* peer) {
    if (peer == NULL) {
        return 0;
    }
    
    // ECDH context'i başlat
    if (!ecdh_init_context(&peer->ecdh_ctx)) {
        PRINTF_LOG("P2P: ECDH context başlatılamadı: %s\n", peer->node_id);
        return 0;
    }
    
    // Anahtar çifti üret
    if (!ecdh_generate_keypair(&peer->ecdh_ctx)) {
        PRINTF_LOG("P2P: ECDH anahtar çifti üretilemedi: %s\n", peer->node_id);
        ecdh_cleanup_context(&peer->ecdh_ctx);
        return 0;
    }
    
    peer->ecdh_initialized = true;
    PRINTF_LOG("P2P: ECDH başlatıldı: %s\n", peer->node_id);
    
    return 1;
}

/**
 * @brief Peer ile ECDH anahtar değişimi yapar
 * @param peer Anahtar değişimi yapılacak peer
 * @return 1 başarı, 0 hata
 * @ingroup p2p_networking
 */
int p2p_exchange_keys_with_peer(p2p_peer_t* peer) {
    if (peer == NULL || !peer->ecdh_initialized || peer->socket_fd < 0) {
        return 0;
    }
    
    PRINTF_LOG("P2P: Peer ile anahtar değişimi başlıyor: %s\n", peer->node_id);
    
    // Önce kendi public key'imizi gönder
    ssize_t sent = send(peer->socket_fd, peer->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
    if (sent != ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("P2P: Public key gönderilemedi: %s\n", peer->node_id);
        return 0;
    }
    
    // Peer'in public key'ini al
    uint8_t peer_public_key[ECC_PUB_KEY_SIZE];
    ssize_t received = recv(peer->socket_fd, peer_public_key, ECC_PUB_KEY_SIZE, 0);
    if (received != ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("P2P: Peer public key alınamadı: %s\n", peer->node_id);
        return 0;
    }
    
    // Shared secret hesapla
    if (!ecdh_compute_shared_secret(&peer->ecdh_ctx, peer_public_key)) {
        PRINTF_LOG("P2P: Shared secret hesaplanamadı: %s\n", peer->node_id);
        return 0;
    }
    
    // AES anahtarını türet
    if (!ecdh_derive_aes_key(&peer->ecdh_ctx)) {
        PRINTF_LOG("P2P: AES anahtarı türetilemedi: %s\n", peer->node_id);
        return 0;
    }
    
    PRINTF_LOG("P2P: ✓ Anahtar değişimi tamamlandı: %s\n", peer->node_id);
    
    return 1;
}

/**
 * @brief Peer için ECDH context'ini temizler
 * @param peer Temizlenecek peer
 * @ingroup p2p_networking
 */
void p2p_cleanup_ecdh_for_peer(p2p_peer_t* peer) {
    if (peer != NULL && peer->ecdh_initialized) {
        ecdh_cleanup_context(&peer->ecdh_ctx);
        peer->ecdh_initialized = false;
        PRINTF_LOG("P2P: ECDH temizlendi: %s\n", peer->node_id);
    }
}

/**
 * @brief ECDH ile şifrelenmiş P2P veriyi işler
 * @param encrypted_data Hex formatında şifreli veri
 * @param filename Dosya adı
 * @param peer ECDH session'ı olan peer
 * @return 0 başarı, -1 hata
 * @ingroup p2p_networking
 */
int p2p_process_encrypted_data(const char* encrypted_data, const char* filename, p2p_peer_t* peer) {
    if (peer == NULL || !peer->ecdh_initialized) {
        PRINTF_LOG("P2P: ECDH session bulunamadı\n");
        return -1;
    }
    
    PRINTF_LOG("P2P: Şifreli veri işleniyor: %s (Peer: %s)\n", filename, peer->node_id);
    
    // Hex string'i bytes'a çevir
    size_t encrypted_length;
    uint8_t* encrypted_bytes = hex_to_bytes(encrypted_data, &encrypted_length);
    
    if (encrypted_bytes == NULL) {
        PRINTF_LOG("P2P: Geçersiz hex format\n");
        return -1;
    }
    
    // IV'yi ayıkla (ilk 16 byte)
    if (encrypted_length < CRYPTO_IV_SIZE) {
        free(encrypted_bytes);
        PRINTF_LOG("P2P: Yetersiz veri boyutu (IV eksik)\n");
        return -1;
    }
    
    uint8_t iv[CRYPTO_IV_SIZE];
    memcpy(iv, encrypted_bytes, CRYPTO_IV_SIZE);
    
    // Şifreli veriyi decrypt et
    char* decrypted_json = decrypt_data(
        encrypted_bytes + CRYPTO_IV_SIZE,
        encrypted_length - CRYPTO_IV_SIZE,
        peer->ecdh_ctx.aes_key, // ECDH session key
        iv
    );
    
    free(encrypted_bytes);
    
    if (decrypted_json == NULL) {
        PRINTF_LOG("P2P: Decryption başarısız\n");
        return -1;
    }
    
    PRINTF_LOG("P2P: Veri başarıyla decrypt edildi\n");
    
    // JSON'u parse et (tactical data format)
    tactical_data_t* tactical_data = parse_json_to_tactical_data(decrypted_json, filename);
    free(decrypted_json);
    
    if (tactical_data != NULL) {
        // Database'e kaydet
        char* response = db_save_tactical_data_and_get_response(tactical_data, filename);
        if (response) {
            PRINTF_LOG("P2P: Database save response: %s\n", response);
            free(response);
        }
        
        free_tactical_data(tactical_data);
        
        PRINTF_LOG("P2P: Şifreli veri başarıyla kaydedildi: %s\n", filename);
        return 0;
    } else {
        PRINTF_LOG("P2P: Geçersiz tactical data formatı\n");
        if (tactical_data) free_tactical_data(tactical_data);
        return -1;
    }
}
