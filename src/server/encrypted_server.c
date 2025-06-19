#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
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
#include "connection_manager.h"
#include "control_interface.h"

// Function prototypes
int parse_protocol_message(const char* message, char** command, char** filename, char** content);
void* handle_client(void* arg);
char* handle_encrypted_request(const char* filename, const char* encrypted_content);
void* queue_processor(void* arg);
void handle_signal(int sig);

// Global variables for signal handling
static volatile sig_atomic_t server_running = 1;

// Signal handler for graceful shutdown
void handle_signal(int sig) {
    printf("\n🛑 Signal %d alındı, server kapatılıyor...\n", sig);
    server_running = 0;
    
    // TCP server'ı durdur
    stop_tcp_server();
    
    // Database'i kapat
    db_close();
    
    printf("✓ Server temiz bir şekilde kapatıldı\n");
    exit(0);
}

int main() {
    printf("Encrypted JSON Server - Sifreli dosya parse sunucusu\n");
    printf("===================================================\n");
    
    // Connection Manager'ı başlat
    if (init_connection_manager() != 0) {
        fprintf(stderr, "Connection Manager başlatılamadı!\n");
        exit(EXIT_FAILURE);
    }
    
    // Control interface'i başlat
    if (start_control_interface() != 0) {
        fprintf(stderr, "Control interface başlatılamadı!\n");
        exit(EXIT_FAILURE);
    }
    
    // Thread monitoring sistemini başlat
    init_thread_monitoring();

    pthread_t monitor_thread;
    pthread_create(&monitor_thread, NULL, thread_monitor, NULL);
    pthread_detach(monitor_thread);
    
    // Queue processor thread'ini başlat
    pthread_t queue_thread;
    pthread_create(&queue_thread, NULL, queue_processor, NULL);
    pthread_detach(queue_thread);
    
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
    
    // TCP Server'ı başlat
    printf("TCP Server başlatılıyor...\n");
    if (start_tcp_server(CONFIG_PORT) != 0) {
        fprintf(stderr, "TCP Server başlatılamadı!\n");
        db_close();
        exit(EXIT_FAILURE);
    }
    
    
    printf("Server başlatıldı\n");
    printf("Desteklenen komutlar:\n");
    printf("  PARSE:filename:{json_data}      - Normal JSON parse\n");
    printf("  ENCRYPTED:filename:{hex_data}   - Sifreli JSON parse\n");
    printf("  CONTROL:command                 - Server control\n");
    printf("Control komutları: start_tcp, stop_tcp, list, stats\n");
    printf("Çıkış için Ctrl+C'ye basın\n\n");
    fflush(stdout);
    
    // Docker modunu kontrol et (stdin kullanılabilir mi?)
    bool is_interactive = isatty(STDIN_FILENO);
    
    if (is_interactive) {
        // Interactive mode - local çalıştırma
        printf("\n=== SERVER CONTROL INTERFACE ===\n");
        printf("Commands: stop_tcp, start_tcp, list, stats, help, quit\n");
        
        char command[256];
        while (1) {
            printf("server> ");
            fflush(stdout);
            
            if (fgets(command, sizeof(command), stdin) != NULL) {
                command[strcspn(command, "\n")] = 0;
                
                if (strlen(command) == 0) continue;
                
                if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0) {
                    printf("Server kapatılıyor...\n");
                    break;
                } else if (strcmp(command, "help") == 0) {
                    show_connection_menu();
                } else if (strcmp(command, "stats") == 0) {
                    list_active_connections();
                    log_thread_stats();
                } else {
                    if (process_connection_command(command) != 0) {
                        printf("Bilinmeyen komut: %s\n", command);
                        printf("'help' yazın veya 'quit' ile çıkın\n");
                    }
                }
            } else {
                break;
            }
        }
    } else {
        // Non-interactive mode - Docker çalıştırma
        printf("\n=== DOCKER MODE - Server running in background ===\n");
        printf("Server TCP port %d'de çalışıyor\n", CONFIG_PORT);
        printf("UDP server için 'start_udp' komutu ile başlatabilirsiniz\n");
        printf("Container'ı durdurmak için: docker-compose down\n");
        fflush(stdout);
        
        // Signal handler kurulumu
        signal(SIGTERM, handle_signal);
        signal(SIGINT, handle_signal);
        
        // Sonsuz döngü - sadece signal ile çıkılır
        while (server_running) {
            sleep(10);
            
            // Her 10 saniyede bir stats yazdır
            printf("=== SERVER STATUS ===\n");
            list_active_connections();
            log_thread_stats();
            printf("Server aktif, bağlantı bekleniyor... (PID: %d)\n", getpid());
            fflush(stdout);
        }
    }
    
    printf("Sunucu kapatılıyor...\n");
    stop_tcp_server();
    db_close();
    printf("Server kapatıldı\n");
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
            printf("HEALTHCHECK: Docker health check tespit edildi (Thread: %lu)\n", current_thread);
            fflush(stdout);
            close(client_socket);
            remove_thread_info(current_thread);
            return NULL;
        }
        
        // Boş veya çok kısa mesajları health check olarak değerlendir
        if (bytes_received < 5) {
            printf("HEALTHCHECK: Kısa mesaj - muhtemelen health check (Thread: %lu, Boyut: %zd)\n", 
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
            printf("Normal JSON parse ediliyor (Tactical Data format)...\n");
            fflush(stdout);
            
            // JSON'u tactical data struct'ına parse et
            tactical_data_t* tactical_data = parse_json_to_tactical_data(content, filename);
            if (tactical_data != NULL && tactical_data->is_valid) {
                // Tactical data'yı database'e kaydet ve response al
                parsed_result = db_save_tactical_data_and_get_response(tactical_data, filename);
                free_tactical_data(tactical_data);
            } else {
                parsed_result = malloc(256);
                strcpy(parsed_result, "HATA: JSON tactical data formatına uygun değil");
                if (tactical_data) free_tactical_data(tactical_data);
            }
        } else if (strcmp(command, "ENCRYPTED") == 0) {
            printf("Sifreli JSON parse ediliyor (Tactical Data format)...\n");
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
    
    // JSON'u tactical data struct'ına parse et
    tactical_data_t* tactical_data = parse_json_to_tactical_data(decrypted_json, filename);
    char* result;
    
    if (tactical_data != NULL && tactical_data->is_valid) {
        // Tactical data'yı database'e kaydet ve response al
        result = db_save_tactical_data_and_get_response(tactical_data, filename);
        free_tactical_data(tactical_data);
    } else {
        result = malloc(256);
        strcpy(result, "HATA: Decrypted JSON tactical data formatına uygun değil");
        if (tactical_data) free_tactical_data(tactical_data);
    }
    
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


