#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <cjson/cJSON.h>
#include <pthread.h>
#include "crypto_utils.h"
#include "json_utils.h"
#include "database.h"
#include "config.h"
#include "thread_monitor.h"

// Function prototypes
int parse_protocol_message(const char* message, char** command, char** filename, char** content);
void* handle_client(void* arg);
char* handle_encrypted_request(const char* filename, const char* encrypted_content);
void* queue_processor(void* arg);

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Thread monitoring sistemini başlat
    init_thread_monitoring();

    pthread_t monitor_thread;
    pthread_create(&monitor_thread, NULL, thread_monitor, NULL);
    pthread_detach(monitor_thread);
    
    // Queue processor thread'ini başlat
    pthread_t queue_thread;
    pthread_create(&queue_thread, NULL, queue_processor, NULL);
    pthread_detach(queue_thread);
    
    printf("Encrypted JSON Server - Sifreli dosya parse sunucusu\n");
    printf("===================================================\n");
    printf("Thread monitoring sistemi aktif\n");
    printf("Queue processing sistemi aktif\n");
    fflush(stdout);
    
    // Database baslat
    printf("Database baslatiiliyor...\n");
    fflush(stdout);
    
    if (db_init("data/tactical_data.db") != 0) {
        fprintf(stderr, "Database baglantisi basarisiz!\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (db_create_tables() != 0) {
        fprintf(stderr, "Database tablolari olusturulamadi!\n");
        fflush(stderr);
        db_close();
        exit(EXIT_FAILURE);
    }
    
    printf("Database basariyla baslatildi ve tablolar hazir\n");
    
    // Test verilerini yükle (sadece ilk çalıştırmada)
    printf("Test verileri kontrol ediliyor...\n");
    unit_t *existing_units;
    int unit_count;
    
    if (db_select_units(&existing_units, &unit_count) == 0) {
        if (unit_count == 0) {
            printf("Database boş, test verileri ekleniyor...\n");
            if (db_insert_test_data() == 0) {
                printf("Test verileri başarıyla eklendi\n");
            } else {
                printf("Test verileri eklenirken hata oluştu\n");
            }
        } else {
            printf("Database'de %d birim mevcut, test verileri atlanıyor\n", unit_count);
        }
        if (existing_units) free(existing_units);
    }
    
    fflush(stdout);
    
    // Socket olustur
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket olusturma hatasi");
        db_close();
        exit(EXIT_FAILURE);
    }
    
    // Socket secenekleri
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt hatasi");
        db_close();
        exit(EXIT_FAILURE);
    }
    
    // Adres konfigurasyonu
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(CONFIG_PORT);
    
    // Socket'i porta bagla
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind hatasi");
        db_close();
        exit(EXIT_FAILURE);
    }
    
    // Dinlemeye basla
    if (listen(server_fd, CONFIG_MAX_CLIENTS) < 0) {
        perror("Listen hatasi");
        db_close();
        exit(EXIT_FAILURE);
    }
    
    printf("Server baslatildi\n");
    printf("Port %d'de sifreli JSON parse istekleri bekleniyor...\n", CONFIG_PORT);
    printf("Desteklenen komutlar:\n");
    printf("  PARSE:filename:{json_data}      - Normal JSON parse\n");
    printf("  ENCRYPTED:filename:{hex_data}   - Sifreli JSON parse\n");
    printf("Cikis icin Ctrl+C'ye basin\n\n");
    fflush(stdout);
    
    while (1) {
        printf("Yeni baglanti bekleniyor...\n");
        fflush(stdout);
        
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept hatasi");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(address.sin_port);
        
        // Health check detection - Docker daemon IP'si veya localhost kontrolü
        if (strcmp(client_ip, "172.17.0.1") == 0 || strcmp(client_ip, "127.0.0.1") == 0) {
            printf("🔍 HEALTHCHECK: Docker health check bağlantısı tespit edildi: %s:%d\n", 
                   client_ip, client_port);
            increment_healthcheck_count();
            increment_total_connections();
            fflush(stdout);
            close(new_socket);
            continue;
        }
        
        printf("✅ CLIENT: Gerçek client bağlantısı: %s:%d (socket_fd: %d)\n", 
               client_ip, client_port, new_socket);
        increment_total_connections();

        // Thread kapasitesi kontrolü
        if (get_active_thread_count() >= CONFIG_MAX_CLIENTS) {
            printf("⚠️  Server dolu! Client queue'ya ekleniyor: %s:%d\n", client_ip, client_port);
            
            // Client'ı queue'ya ekle
            add_to_queue(new_socket, address);
            continue;
        }
        
        pthread_t thread_id;
        int *client_socket_ptr = malloc(sizeof(int));
        *client_socket_ptr = new_socket;

        if (pthread_create(&thread_id, NULL, handle_client, client_socket_ptr) != 0) {
            perror("Thread olusturma hatasi");
            free(client_socket_ptr);
            close(new_socket);
            continue;
        }

        add_thread_info(thread_id, new_socket, client_ip, client_port);

        
        pthread_detach(thread_id);
        printf("Client thread olusturuldu (Thread ID: %lu, Aktif: %d)\n", 
               thread_id, get_active_thread_count());
        fflush(stdout);
    }
    
    close(server_fd);
    db_close();
    printf("Server kapatildi ve database baglantisi sonlandirildi\n");
    fflush(stdout);
    return 0;
}

// Client ile iletisimi yonet
void* handle_client(void* arg) {
    int client_socket = *(int*)arg;
    pthread_t current_thread = pthread_self();
    free(arg); // malloc'ed memory'yi temizle

    printf("Client thread baslatildi (Thread ID: %lu, Socket: %d)\n", 
           current_thread, client_socket);
    fflush(stdout);

    char buffer[CONFIG_BUFFER_SIZE];
    int request_count = 0;
    
    while (1) {
        memset(buffer, 0, CONFIG_BUFFER_SIZE);
        
        ssize_t bytes_received = read(client_socket, buffer, CONFIG_BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("Client normal olarak ayrıldı (Thread: %lu)\n", current_thread);
            } else {
                printf("Client bağlantı hatası (Thread: %lu, Hata: %s)\n", 
                       current_thread, strerror(errno));
            }
            break;
        }
        
        request_count++;
        printf("İstek alındı (Thread: %lu, İstek #%d, Boyut: %zd bytes)\n", 
               current_thread, request_count, bytes_received);
        
        buffer[bytes_received] = '\0';
        
        // Health check detection - Docker healthcheck'i tespit et
        if (bytes_received == 0 || (bytes_received > 0 && buffer[0] == '\0')) {
            printf("🔍 HEALTHCHECK: Docker health check tespit edildi (Thread: %lu)\n", current_thread);
            fflush(stdout);
            close(client_socket);
            remove_thread_info(current_thread);
            return NULL;
        }
        
        // Boş veya çok kısa mesajları health check olarak değerlendir
        if (bytes_received < 5) {
            printf("🔍 HEALTHCHECK: Kısa mesaj - muhtemelen health check (Thread: %lu, Boyut: %zd)\n", 
                   current_thread, bytes_received);
            fflush(stdout);
            close(client_socket);
            remove_thread_info(current_thread);
            return NULL;
        }
        
        char *current_time = get_current_time();
        printf("[%s] Mesaj alindi (%zd byte)\n", current_time, bytes_received);
        fflush(stdout);
        free(current_time);
        
        // Protokol mesajini parse et
        char *command = NULL;
        char *filename = NULL;
        char *content = NULL;
        
        if (parse_protocol_message(buffer, &command, &filename, &content) != 0) {
            char *error_response = "HATA: Gecersiz protokol formati. Format: COMMAND:FILENAME:CONTENT";
            send(client_socket, error_response, strlen(error_response), 0);
            continue;
        }
        
        printf("Komut: %s\n", command);
        printf("Dosya: %s\n", filename);
        fflush(stdout);
        
        char *parsed_result = NULL;
        
        // Komut tipine gore islem yap
        if (strcmp(command, "PARSE") == 0) {
            printf("Normal JSON parse ediliyor...\n");
            fflush(stdout);
            parsed_result = parse_json_to_string(content, filename);
        } else if (strcmp(command, "ENCRYPTED") == 0) {
            printf("Sifreli JSON parse ediliyor...\n");
            fflush(stdout);
            parsed_result = handle_encrypted_request(filename, content);
        } else {
            parsed_result = malloc(256);
            snprintf(parsed_result, 256, "HATA: Bilinmeyen komut: %s", command);
        }
        
        // Sonucu client'a gonder
        if (parsed_result != NULL) {
            send(client_socket, parsed_result, strlen(parsed_result), 0);
            printf("Parse sonucu gonderildi\n");
            fflush(stdout);
            free(parsed_result);
        }
        
        // Bellek temizligi
        free(command);
        free(filename);
        free(content);
    }

    close(client_socket);
    printf("Client bağlantısı kapatıldı (Thread: %lu, Toplam istek: %d)\n", 
           current_thread, request_count);
    
    // Thread bilgilerini temizle
    remove_thread_info(current_thread);
    
    printf("✅ Thread slot serbest kaldı - Queue kontrol ediliyor...\n");
    fflush(stdout);
    
    fflush(stdout);
    return NULL; // void* döndürmek için
}

// Sifreli istek ile bas et
char* handle_encrypted_request(const char* filename, const char* encrypted_content) {
    // Hex string'i bytes'a cevir
    size_t encrypted_length;
    uint8_t* encrypted_bytes = hex_to_bytes(encrypted_content, &encrypted_length);
    
    if (encrypted_bytes == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Gecersiz hex format");
        return error_msg;
    }
    
    // IV'yi ayikla (ilk 16 byte)
    if (encrypted_length < CRYPTO_IV_SIZE) {
        free(encrypted_bytes);
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Yetersiz veri boyutu (IV eksik)");
        return error_msg;
    }
    
    uint8_t iv[CRYPTO_IV_SIZE];
    memcpy(iv, encrypted_bytes, CRYPTO_IV_SIZE);
    
    // Sifreli veriyi decrypt et
    char* decrypted_json = decrypt_data(
        encrypted_bytes + CRYPTO_IV_SIZE,
        encrypted_length - CRYPTO_IV_SIZE,
        NULL, // Default key kullan
        iv
    );
    
    free(encrypted_bytes);
    
    if (decrypted_json == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Decryption basarisiz");
        return error_msg;
    }
    
    printf("Decrypted JSON: %s\n", decrypted_json);
    
    // JSON'u parse et
    char* result = parse_json_to_string(decrypted_json, filename);
    free(decrypted_json);
    
    return result;
}

// Protokol mesajini parse et: "COMMAND:FILENAME:CONTENT"
int parse_protocol_message(const char* message, char** command, char** filename, char** content) {
    char* first_colon = strchr(message, ':');
    if (first_colon == NULL) {
        return -1;
    }
    
    char* second_colon = strchr(first_colon + 1, ':');
    if (second_colon == NULL) {
        return -1;
    }
    
    size_t command_length = first_colon - message;
    size_t filename_length = second_colon - first_colon - 1;
    size_t content_length = strlen(second_colon + 1);
    
    *command = malloc(command_length + 1);
    *filename = malloc(filename_length + 1);
    *content = malloc(content_length + 1);
    
    if (*command == NULL || *filename == NULL || *content == NULL) {
        if (*command) free(*command);
        if (*filename) free(*filename);
        if (*content) free(*content);
        return -1;
    }
    
    strncpy(*command, message, command_length);
    (*command)[command_length] = '\0';
    
    strncpy(*filename, first_colon + 1, filename_length);
    (*filename)[filename_length] = '\0';
    
    strcpy(*content, second_colon + 1);
    
    return 0;
}

// Queue processor thread - boş slot olduğunda queue'yu işler
void* queue_processor(void* arg) {
    (void)arg; // unused parameter warning'ini bastır
    
    printf("Queue processor thread başlatıldı\n");
    fflush(stdout);
    
    while (1) {
        // Queue'da client var mı ve boş thread slot'u var mı kontrol et
        while (get_queue_size() > 0 && get_active_thread_count() < CONFIG_MAX_CLIENTS) {
            printf("🔄 Queue işleniyor... (Queue: %d, Aktif: %d/%d)\n", 
                   get_queue_size(), get_active_thread_count(), CONFIG_MAX_CLIENTS);
            
            if (process_queue() == 0) {
                break; // Queue boş
            }
            
            // Thread oluşturma sonrası kısa bekleme
            sleep(100000); // 100ms
        }
        
        // Queue kontrol aralığı
        sleep(CONFIG_QUEUE_CHECK_INTERVAL);
    }
    
    return NULL;
}


