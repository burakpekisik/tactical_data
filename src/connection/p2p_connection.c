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

static p2p_peer_t peers[CONFIG_MAX_CLIENTS];
static int peer_count = 0;
static pthread_mutex_t p2p_mutex = PTHREAD_MUTEX_INITIALIZER;
static char local_node_id[128];

typedef struct {
    int socket;
    connection_manager_t* manager;
} peer_handler_params_t;

// P2P Node başlatma
int p2p_node_init(connection_manager_t* manager) {
    printf("P2P Node modülü başlatılıyor...\n");
    
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
    
    printf("✓ P2P Node modülü hazır (Port: %d, NodeID: %s)\n", 
           manager->port, local_node_id);
    return 0;
}

// P2P Node başlat
int p2p_node_start(connection_manager_t* manager) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    printf("P2P Node başlatılıyor (Port: %d)...\n", manager->port);
    
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
    
    printf("✓ P2P Node başarıyla başlatıldı (Port: %d, NodeID: %s)\n", 
           manager->port, local_node_id);
    return 0;
}

// P2P Node durdur
int p2p_node_stop(connection_manager_t* manager) {
    if (manager->status != CONN_STATUS_RUNNING) {
        printf("P2P Node zaten durdurulmuş\n");
        return 0;
    }
    
    printf("P2P Node durduruluyor...\n");
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
    
    printf("✓ P2P Node durduruldu (Port: %d)\n", manager->port);
    return 0;
}

// P2P Node ana thread
void* p2p_node_thread(void* arg) {
    connection_manager_t* manager = (connection_manager_t*)arg;
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    
    printf("P2P Node thread başlatıldı (Port: %d, NodeID: %s)\n", 
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
        
        printf("P2P Yeni peer bağlantısı: %s:%d\n", peer_ip, peer_port);
        
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
            printf("P2P Maksimum peer sayısına ulaşıldı, bağlantı reddediliyor\n");
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
    
    printf("P2P Node thread sonlandırıldı\n");
    return NULL;
}

// Peer'i listeye ekle
int p2p_add_peer(const char* ip, int port) {
    pthread_mutex_lock(&p2p_mutex);
    
    if (peer_count >= CONFIG_MAX_CLIENTS) {
        pthread_mutex_unlock(&p2p_mutex);
        printf("P2P Maksimum peer sayısına ulaşıldı\n");
        return -1;
    }
    
    // Zaten var mı kontrol et
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].ip, ip) == 0 && peers[i].port == port) {
            pthread_mutex_unlock(&p2p_mutex);
            printf("P2P Peer zaten mevcut: %s:%d\n", ip, port);
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
    
    printf("P2P Yeni peer eklendi: %s:%d (NodeID: %s)\n", 
           ip, port, peers[peer_count-1].node_id);
    
    pthread_mutex_unlock(&p2p_mutex);
    return 0;
}

// Peer'i listeden kaldır
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
            
            printf("P2P Peer kaldırıldı: %s\n", node_id);
            p2p_log_peer_activity(node_id, "REMOVED");
            
            pthread_mutex_unlock(&p2p_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&p2p_mutex);
    printf("P2P Peer bulunamadı: %s\n", node_id);
    return -1;
}

// Peer'e bağlan
int p2p_connect_to_peer(p2p_peer_t* peer) {
    if (peer->is_connected) {
        printf("P2P Peer zaten bağlı: %s:%d\n", peer->ip, peer->port);
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
    
    printf("P2P Peer'e bağlandı: %s:%d\n", peer->ip, peer->port);
    p2p_log_peer_activity(peer->node_id, "CONNECTED");
    
    return 0;
}

// Peer bağlantısını kes
int p2p_disconnect_from_peer(p2p_peer_t* peer) {
    if (!peer->is_connected) {
        return 0;
    }
    
    if (peer->socket_fd >= 0) {
        close(peer->socket_fd);
        peer->socket_fd = -1;
    }
    
    peer->is_connected = false;
    
    printf("P2P Peer bağlantısı kesildi: %s:%d\n", peer->ip, peer->port);
    p2p_log_peer_activity(peer->node_id, "DISCONNECTED");
    
    return 0;
}

// Peer mesajını işle
void p2p_handle_peer_message(int socket, connection_manager_t* manager) {
    char buffer[CONFIG_BUFFER_SIZE];
    
    while (1) {
        memset(buffer, 0, CONFIG_BUFFER_SIZE);
        
        ssize_t bytes_received = recv(socket, buffer, CONFIG_BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("P2P Peer bağlantısı kesildi (socket: %d)\n", socket);
            break;
        }
        
        buffer[bytes_received] = '\0';
        printf("P2P Mesaj alındı (%zd bytes): %.100s%s\n", 
               bytes_received, buffer, bytes_received > 100 ? "..." : "");
        
        // P2P mesajını işle
        if (strncmp(buffer, "P2P_DATA:", 9) == 0) {
            // Tactical data mesajı
            char* data_part = buffer + 9;
            printf("P2P Tactical data işleniyor...\n");
            
            // P2P protokol formatını parse et
            if (process_p2p_tactical_data(data_part) == 0) {
                const char* response = "P2P_ACK:Data processed successfully";
                send(socket, response, strlen(response), 0);
                printf("P2P Tactical data başarıyla işlendi\n");
            } else {
                const char* response = "P2P_NACK:Data processing failed";
                send(socket, response, strlen(response), 0);
                printf("P2P Tactical data işleme hatası\n");
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
    
    close(socket);
}

// Broadcast mesajı gönder
int p2p_broadcast_message(const char* message) {
    int sent_count = 0;
    
    pthread_mutex_lock(&p2p_mutex);
    
    for (int i = 0; i < peer_count; i++) {
        if (peers[i].is_connected && peers[i].socket_fd >= 0) {
            if (send(peers[i].socket_fd, message, strlen(message), 0) > 0) {
                sent_count++;
                printf("P2P Broadcast gönderildi: %s -> %s\n", 
                       message, peers[i].node_id);
            }
        }
    }
    
    pthread_mutex_unlock(&p2p_mutex);
    
    printf("P2P Broadcast tamamlandı: %d peer'e gönderildi\n", sent_count);
    return sent_count;
}

// İstatistikleri güncelle
void p2p_update_stats(connection_manager_t* manager) {
    manager->client_count = peer_count;
    printf("P2P Stats: Connected peers=%d, Total requests=%d\n", 
           manager->client_count, manager->total_requests);
}

// Peer aktivitesini logla
void p2p_log_peer_activity(const char* node_id, const char* activity) {
    time_t now = time(NULL);
    char* time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // newline'ı kaldır
    
    printf("[%s] P2P %s: %s\n", time_str, activity, node_id);
}

// Peer sayısını al
int p2p_get_peer_count(void) {
    pthread_mutex_lock(&p2p_mutex);
    int count = peer_count;
    pthread_mutex_unlock(&p2p_mutex);
    return count;
}

// Peer listesini göster
void p2p_list_peers(void) {
    pthread_mutex_lock(&p2p_mutex);
    
    printf("\n=== P2P PEER LIST ===\n");
    printf("Local Node ID: %s\n", local_node_id);
    printf("Connected Peers: %d\n", peer_count);
    
    for (int i = 0; i < peer_count; i++) {
        printf("  [%d] %s:%d (%s) - %s\n", 
               i + 1,
               peers[i].ip, 
               peers[i].port,
               peers[i].node_id,
               peers[i].is_connected ? "CONNECTED" : "DISCONNECTED");
    }
    
    printf("====================\n\n");
    
    pthread_mutex_unlock(&p2p_mutex);
}

// P2P Tactical data processing - UDP ile aynı logic
int process_tactical_data(const char* data) {
    if (data == NULL || strlen(data) == 0) {
        printf("P2P Boş data alındı\n");
        return -1;
    }
    
    tactical_data_t* tactical_data = NULL;
    
    // Eğer hex format ise decrypt et
    if (strstr(data, "\"encrypted_data\":") != NULL) {
        printf("P2P Şifreli data decrypt ediliyor...\n");
        
        // JSON parse ederek encrypted_data değerini al
        cJSON* json = cJSON_Parse(data);
        if (!json) {
            printf("P2P Error: JSON parse failed\n");
            return -1;
        }
        
        cJSON* encrypted_data_obj = cJSON_GetObjectItem(json, "encrypted_data");
        if (!encrypted_data_obj || !cJSON_IsString(encrypted_data_obj)) {
            printf("P2P Error: encrypted_data field not found\n");
            cJSON_Delete(json);
            return -1;
        }
        
        const char* encrypted_hex = cJSON_GetStringValue(encrypted_data_obj);
        
        // Hex data'yı decode et
        size_t binary_len;
        uint8_t* binary_data = hex_to_bytes(encrypted_hex, &binary_len);
        cJSON_Delete(json);
        
        if (!binary_data) {
            printf("P2P Encrypted Error: Hex decode failed\n");
            return -1;
        }
        
        // Decrypt data - IV ilk 16 byte'ta
        if (binary_len < 16) {
            printf("P2P Encrypted Error: Data too short for IV\n");
            free(binary_data);
            return -1;
        }
        
        uint8_t* iv = binary_data;
        uint8_t* ciphertext = binary_data + 16;
        size_t ciphertext_len = binary_len - 16;
        
        char* decrypted_json = decrypt_data(ciphertext, ciphertext_len, CONFIG_DEFAULT_KEY, iv);
        free(binary_data);
        
        if (!decrypted_json) {
            printf("P2P Encrypted Error: Decryption failed\n");
            return -1;
        }
        
        printf("P2P: Data decrypted successfully\n");
        
        // Şifrelenmiş JSON'u çöz
        tactical_data = parse_json_to_tactical_data(decrypted_json, "p2p_data");
        free(decrypted_json);
    } else {
        printf("P2P Normal data processing\n");
        // Normal JSON processing
        tactical_data = parse_json_to_tactical_data(data, "p2p_data");
    }
    
    if (tactical_data != NULL && tactical_data->is_valid) {
        printf("P2P: Tactical data parsed successfully\n");
        
        // Database'e kaydet
        char* response = db_save_tactical_data_and_get_response(tactical_data, "p2p_data");
        if (response) {
            printf("P2P: Database save response: %s\n", response);
            free(response);
        }
        
        free_tactical_data(tactical_data);
        
        printf("P2P Success: Data saved to database\n");
        return 0;
    } else {
        printf("P2P Error: Invalid tactical data format\n");
        if (tactical_data) free_tactical_data(tactical_data);
        return -1;
    }
}

// P2P Protocol format processing: CLIENT_ID:TYPE:FILENAME:DATA
int process_p2p_tactical_data(const char* p2p_data) {
    if (p2p_data == NULL || strlen(p2p_data) == 0) {
        printf("P2P Boş protocol data alındı\n");
        return -1;
    }
    
    printf("P2P Protocol data: %.100s%s\n", p2p_data, strlen(p2p_data) > 100 ? "..." : "");
    
    // P2P formatını parse et: CLIENT_ID:TYPE:FILENAME:DATA
    size_t data_len = strlen(p2p_data);
    char* data_copy = malloc(data_len + 1);
    if (!data_copy) {
        printf("P2P Memory allocation failed\n");
        return -1;
    }
    strcpy(data_copy, p2p_data);
    
    char* client_id = strtok(data_copy, ":");
    char* data_type = strtok(NULL, ":");
    char* filename = strtok(NULL, ":");
    char* json_data = strtok(NULL, "");  // Rest of the string
    
    if (!client_id || !data_type || !filename || !json_data) {
        printf("P2P Invalid protocol format\n");
        free(data_copy);
        return -1;
    }
    
    printf("P2P Parse: Client=%s, Type=%s, File=%s\n", client_id, data_type, filename);
    
    int result = -1;
    
    if (strcmp(data_type, "ENCRYPTED") == 0) {
        printf("P2P Encrypted data processing\n");
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
        printf("P2P Normal data processing\n");
        // Normal JSON data
        result = process_tactical_data(json_data);
    } else {
        printf("P2P Unknown data type: %s\n", data_type);
    }
    
    free(data_copy);
    return result;
}

int p2p_send_keepalive(p2p_peer_t* peer) {
    if (peer && peer->is_connected) {
        const char* keepalive_msg = "P2P_KEEPALIVE";
        send(peer->socket_fd, keepalive_msg, strlen(keepalive_msg), 0);
        peer->last_seen = time(NULL);
        return 0;
    }
    return -1;
}

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

// P2P peer thread wrapper fonksiyunu
void* p2p_peer_thread_wrapper(void* arg) {
    peer_handler_params_t* params = (peer_handler_params_t*)arg;
    
    p2p_handle_peer_message(params->socket, params->manager);
    
    free(params);
    return NULL;
}
