/**
 * @file encrypted_server.c
 * @brief Şifreli taktik veri transfer sunucusu - çok threaded JSON işleme servisi
 * @ingroup server
 * @author Taktik Veri Sistemi
 * @date 2025
 * 
 * Bu dosya şifreli taktik veri transferi için ana sunucu uygulamasını içerir.
 * Çok threaded TCP sunucu mimarisi ile ECDH anahtar değişimi ve AES256 
 * şifreleme destekli güvenli veri işleme sağlar.
 * 
 * Ana özellikler:
 * - TCP/UDP çok threaded sunucu desteği
 * - ECDH anahtar değişimi ile güvenli oturum kurulumu
 * - AES256 ile şifreli JSON veri işleme
 * - SQLite veritabanına taktik veri kaydetme
 * - Thread monitoring ve bağlantı yönetimi
 * - Docker desteği (interactive/non-interactive modlar)
 * - Graceful shutdown ve signal handling
 * 
 * Desteklenen protokol komutları:
 * - PARSE:filename:json_data      - Normal JSON parse ve kayıt
 * - ENCRYPTED:filename:hex_data   - Şifreli JSON parse ve kayıt
 * - CONTROL:command               - Sunucu kontrol komutları
 * 
 * @note Bu sunucu production ortamında çalışacak şekilde tasarlanmıştır.
 *       Thread pool, connection queue ve memory management içerir.
 * 
 * @warning Sunucu başlatılmadan önce veritabanı dosyasının erişilebilir
 *          olduğundan emin olun. Test verileri otomatik yüklenir.
 */

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
#include "encrypted_server.h"
#include "logger.h"

/// @brief Sunucu çalışma durumu için global flag - signal handling için
static volatile sig_atomic_t server_running = 1;

/**
 * @brief Graceful shutdown için signal handler
 * @ingroup server
 * 
 * SIGTERM ve SIGINT sinyallerini yakalayarak sunucunun temiz bir şekilde
 * kapatılmasını sağlar. Tüm bağlantıları kapatır ve kaynakları temizler.
 * 
 * Temizlik sırası:
 * 1. TCP sunucusunu durdurur
 * 2. Veritabanı bağlantısını kapatır
 * 3. Konsol mesajı yazdırır
 * 4. Program çıkışı yapar
 * 
 * @param sig Yakalanan sinyal numarası (SIGTERM=15, SIGINT=2)
 * 
 * @note Bu fonksiyon async-signal-safe'dir ve signal context'inde güvenli çalışır
 * @warning exit() çağrısı yapar, program anında sonlanır
 * 
 * @see stop_tcp_server()
 * @see db_close()
 */
// Signal handler for graceful shutdown
void handle_signal(int sig) {
    LOG_SERVER_INFO("Signal %d received, shutting down server...", sig);
    PRINTF_SERVER("\n🛑 Signal %d alındı, server kapatılıyor...\n", sig);
    server_running = 0;
    
    // TCP server'ı durdur
    LOG_SERVER_INFO("Stopping TCP server...");
    stop_tcp_server();
    
    // Database'i kapat
    LOG_SERVER_INFO("Closing database connection...");
    db_close();
    
    // Logger'ı temizle
    logger_cleanup(LOGGER_SERVER);
    
    PRINTF_LOG("✓ Server temiz bir şekilde kapatıldı\n");
    exit(0);
}

/**
 * @brief Şifreli taktik veri sunucusunun ana fonksiyonu
 * @ingroup server
 * 
 * Bu fonksiyon tüm sunucu altyapısını başlatır ve yönetir. Production
 * ortamında interactive ve Docker modlarında çalışabilir.
 * 
 * Başlatma sırası:
 * 1. Connection Manager'ı başlatır
 * 2. Control interface'i başlatır
 * 3. Thread monitoring sistemini başlatır
 * 4. Queue processor thread'ini başlatır
 * 5. Veritabanını başlatır ve tabloları oluşturur
 * 6. Test verilerini kontrol eder ve yükler
 * 7. TCP sunucusunu başlatır
 * 8. Interactive/Docker moduna göre çalışır
 * 
 * İki çalışma modu:
 * - **Interactive Mode**: Local çalıştırma, konsol komutları kabul eder
 * - **Docker Mode**: Background çalışma, signal ile sonlanır
 * 
 * Desteklenen konsol komutları:
 * - quit/exit: Sunucuyu kapat
 * - help: Yardım menüsünü göster
 * - stats: Bağlantı ve thread istatistikleri
 * - start_tcp, stop_tcp: TCP sunucu kontrol
 * 
 * @return 0 başarılı çıkış
 * @return EXIT_FAILURE başlatma hatası durumunda
 * 
 * @note Fonksiyon stdin kontrolü ile Docker/interactive modları ayırt eder.
 *       Docker modunda her 10 saniyede status raporu yazdırır.
 * 
 * @warning Başlatma hatalarında tüm kaynakları temizler ve çıkış yapar.
 *          Signal handler kurulumu Docker modunda aktif edilir.
 * 
 * @see init_connection_manager()
 * @see start_control_interface()
 * @see init_thread_monitoring()
 * @see db_init()
 * @see start_tcp_server()
 * @see handle_signal()
 */

int main() {
    PRINTF_SERVER("Encrypted JSON Server - Sifreli dosya parse sunucusu\n");
    PRINTF_SERVER("===================================================\n");
    
    // Logger'ı başlat (önce logger başlatılmalı)
    if (logger_init(LOGGER_SERVER, LOG_DEBUG) != 0) {
        fprintf(stderr, "Logger başlatılamadı!\n");
        exit(EXIT_FAILURE);
    }
    
    LOG_SERVER_INFO("Starting Encrypted JSON Server...");
    LOG_SERVER_INFO("Server initialization began");
    
    // Connection Manager'ı başlat
    LOG_SERVER_DEBUG("Initializing Connection Manager...");
    if (init_connection_manager() != 0) {
        LOG_SERVER_ERROR("Failed to initialize Connection Manager");
        PRINTF_SERVER("Connection Manager başlatılamadı!\n");
        logger_cleanup(LOGGER_SERVER);
        exit(EXIT_FAILURE);
    }
    LOG_SERVER_INFO("Connection Manager initialized successfully");
    
    // Control interface'i başlat
    LOG_SERVER_DEBUG("Starting Control Interface...");
    if (start_control_interface() != 0) {
        LOG_SERVER_ERROR("Failed to start Control Interface");
        PRINTF_SERVER("Control interface başlatılamadı!\n");
        logger_cleanup(LOGGER_SERVER);
        exit(EXIT_FAILURE);
    }
    LOG_SERVER_INFO("Control Interface started successfully");
    
    // Thread monitoring sistemini başlat
    LOG_SERVER_DEBUG("Initializing Thread Monitoring...");
    init_thread_monitoring();

    pthread_t monitor_thread;
    pthread_create(&monitor_thread, NULL, thread_monitor, NULL);
    pthread_detach(monitor_thread);
    
    // Queue processor thread'ini başlat
    pthread_t queue_thread;
    pthread_create(&queue_thread, NULL, queue_processor, NULL);
    pthread_detach(queue_thread);
    
    LOG_SERVER_INFO("Thread monitoring system activated");
    LOG_SERVER_INFO("Queue processing system activated");
    PRINTF_SERVER("Thread monitoring sistemi aktif\n");
    PRINTF_SERVER("Queue processing sistemi aktif\n");
    fflush(stdout);
    
    // Database baslat
    LOG_SERVER_DEBUG("Initializing database...");
    PRINTF_SERVER("Database baslatiiliyor...\n");
    fflush(stdout);
    
    if (db_init("data/tactical_data.db") != 0) {
        LOG_SERVER_ERROR("Database connection failed!");
        PRINTF_SERVER("Database baglantisi basarisiz!\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (db_create_tables() != 0) {
        LOG_SERVER_ERROR("Failed to create database tables");
        PRINTF_SERVER("Database tablolari olusturulamadi!\n");
        fflush(stderr);
        db_close();
        exit(EXIT_FAILURE);
    }
    
    LOG_SERVER_INFO("Database successfully initialized, tables ready");
    PRINTF_SERVER("Database basariyla baslatildi ve tablolar hazir\n");
    
    // Test verilerini yükle (sadece ilk çalıştırmada)
    LOG_SERVER_DEBUG("Checking test data...");
    PRINTF_SERVER("Test verileri kontrol ediliyor...\n");
    unit_t *existing_units;
    int unit_count;
    
    if (db_select_units(&existing_units, &unit_count) == 0) {
        if (unit_count == 0) {
            LOG_SERVER_INFO("Database empty, inserting test data...");
            PRINTF_SERVER("Database boş, test verileri ekleniyor...\n");
            if (db_insert_test_data() == 0) {
                LOG_SERVER_INFO("Test data inserted successfully");
                PRINTF_SERVER("Test verileri başarıyla eklendi\n");
            } else {
                LOG_SERVER_ERROR("Failed to insert test data");
                PRINTF_SERVER("Test verileri eklenirken hata oluştu\n");
            }
        } else {
            LOG_SERVER_INFO("Database has %d existing units, skipping test data", unit_count);
            PRINTF_SERVER("Database'de %d birim mevcut, test verileri atlanıyor\n", unit_count);
        }
        if (existing_units) free(existing_units);
    }
    
    fflush(stdout);
    
    // TCP Server'ı başlat
    LOG_SERVER_DEBUG("Starting TCP Server...");
    PRINTF_SERVER("TCP Server başlatılıyor...\n");
    if (start_tcp_server(CONFIG_PORT) != 0) {
        LOG_SERVER_ERROR("Failed to start TCP Server");
        PRINTF_SERVER("TCP Server başlatılamadı!\n");
        db_close();
        exit(EXIT_FAILURE);
    }
    
    LOG_SERVER_INFO("Server started successfully");
    PRINTF_SERVER("Server başlatıldı\n");
    PRINTF_SERVER("Desteklenen komutlar:\n");
    PRINTF_SERVER("  PARSE:filename:{json_data}      - Normal JSON parse\n");
    PRINTF_SERVER("  ENCRYPTED:filename:{hex_data}   - Sifreli JSON parse\n");
    PRINTF_SERVER("  CONTROL:command                 - Server control\n");
    PRINTF_SERVER("Control komutları: start_tcp, stop_tcp, list, stats\n");
    PRINTF_SERVER("Çıkış için Ctrl+C'ye basın\n\n");
    fflush(stdout);
    
    // Docker modunu kontrol et (stdin kullanılabilir mi?)
    bool is_interactive = isatty(STDIN_FILENO);
    
    if (is_interactive) {
        // Interactive mode - local çalıştırma
        LOG_SERVER_INFO("Running in interactive mode");
        PRINTF_SERVER("\n=== SERVER CONTROL INTERFACE ===\n");
        PRINTF_LOG("Commands: stop_tcp, start_tcp, list, stats, help, quit\n");
        
        char command[256];
        while (1) {
            PRINTF_LOG("server> ");
            fflush(stdout);
            
            if (fgets(command, sizeof(command), stdin) != NULL) {
                command[strcspn(command, "\n")] = 0;
                
                if (strlen(command) == 0) continue;
                
                if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0) {
                    PRINTF_LOG("Server kapatılıyor...\n");
                    break;
                } else if (strcmp(command, "help") == 0) {
                    show_connection_menu();
                } else if (strcmp(command, "stats") == 0) {
                    list_active_connections();
                    log_thread_stats();
                } else {
                    if (process_connection_command(command) != 0) {
                        PRINTF_LOG("Bilinmeyen komut: %s\n", command);
                        PRINTF_LOG("'help' yazın veya 'quit' ile çıkın\n");
                    }
                }
            } else {
                break;
            }
        }
    } else {
        // Non-interactive mode - Docker çalıştırma
        PRINTF_LOG("\n=== DOCKER MODE - Server running in background ===\n");
        PRINTF_LOG("Server TCP port %d'de çalışıyor\n", CONFIG_PORT);
        PRINTF_LOG("UDP server için 'start_udp' komutu ile başlatabilirsiniz\n");
        PRINTF_LOG("Container'ı durdurmak için: docker-compose down\n");
        fflush(stdout);
        
        // Signal handler kurulumu
        signal(SIGTERM, handle_signal);
        signal(SIGINT, handle_signal);
        
        // Sonsuz döngü - sadece signal ile çıkılır
        while (server_running) {
            sleep(10);
            
            // Her 10 saniyede bir stats yazdır
            PRINTF_LOG("=== SERVER STATUS ===\n");
            list_active_connections();
            log_thread_stats();
            PRINTF_LOG("Server aktif, bağlantı bekleniyor... (PID: %d)\n", getpid());
            fflush(stdout);
        }
    }
    
    PRINTF_LOG("Sunucu kapatılıyor...\n");
    stop_tcp_server();
    db_close();
    PRINTF_LOG("Server kapatıldı\n");
    return 0;
}

/**
 * @brief Client bağlantısını yöneten thread fonksiyonu
 * @ingroup server
 * 
 * Her client bağlantısı için ayrı bir thread'de çalışan ana işleyici fonksiyon.
 * ECDH anahtar değişimi, AES şifreleme ve JSON veri işleme süreçlerini yönetir.
 * 
 * İşlem adımları:
 * 1. ECDH connection manager'ı başlatır
 * 2. Client ile anahtar değişimi yapar
 * 3. AES256 session key'i oluşturur
 * 4. Client mesajlarını dinler ve işler
 * 5. Protokol mesajlarını parse eder
 * 6. PARSE/ENCRYPTED komutlarını yürütür
 * 7. Sonuçları client'a gönderir
 * 8. Bağlantı sonunda temizlik yapar
 * 
 * Desteklenen komutlar:
 * - PARSE:filename:json_data - Normal JSON parse
 * - ENCRYPTED:filename:hex_data - Şifreli JSON parse
 * 
 * Özel durumlar:
 * - Docker health check tespiti (kısa mesajlar)
 * - Boş bağlantılar (0 byte)
 * - Protocol format hataları
 * 
 * @param arg Client socket file descriptor (int* olarak cast edilmiş)
 * 
 * @return NULL (pthread için void* dönüş)
 * 
 * @note Fonksiyon thread-safe'dir ve her client için ayrı çalışır.
 *       Bellek yönetimi tam otomatik, ECDH cleanup dahil.
 * 
 * @warning arg parametresi malloc'lu memory, fonksiyon içinde free edilir.
 *          Thread sonunda slot'u serbest bırakır.
 * 
 * @see init_ecdh_for_connection()
 * @see exchange_keys_with_peer()
 * @see parse_protocol_message()
 * @see handle_encrypted_request()
 * @see remove_thread_info()
 */
// Client ile iletisimi yonet
void* handle_client(void* arg) {
    int client_socket = *(int*)arg;
    pthread_t current_thread = pthread_self();
    free(arg); // malloc'ed memory'yi temizle

    PRINTF_LOG("Client thread baslatildi (Thread ID: %lu, Socket: %d)\n", 
           current_thread, client_socket);
    fflush(stdout);

    // ECDH için anahtar değişimi yap
    connection_manager_t client_manager;
    memset(&client_manager, 0, sizeof(connection_manager_t));
    snprintf(client_manager.name, sizeof(client_manager.name), "Client-%d", client_socket);
    
    if (!init_ecdh_for_connection(&client_manager)) {
        PRINTF_LOG("ECDH başlatılamadı (Thread: %lu)\n", current_thread);
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    
    // Anahtar değişimi yap
    if (!exchange_keys_with_peer(&client_manager, client_socket)) {
        PRINTF_LOG("Anahtar değişimi başarısız (Thread: %lu)\n", current_thread);
        cleanup_ecdh_for_connection(&client_manager);
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    
    // AES256 oturum anahtarını al
    const uint8_t* session_key = get_session_key(&client_manager);
    if (session_key == NULL) {
        PRINTF_LOG("Oturum anahtarı alınamadı (Thread: %lu)\n", current_thread);
        cleanup_ecdh_for_connection(&client_manager);
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    
    PRINTF_LOG("✓ ECDH anahtar değişimi tamamlandı (Thread: %lu)\n", current_thread);

    char buffer[CONFIG_BUFFER_SIZE];
    int request_count = 0;
    
    while (1) {
        memset(buffer, 0, CONFIG_BUFFER_SIZE);
        
        ssize_t bytes_received = read(client_socket, buffer, CONFIG_BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                PRINTF_LOG("Client normal olarak ayrıldı (Thread: %lu)\n", current_thread);
            } else {
                PRINTF_LOG("Client bağlantı hatası (Thread: %lu, Hata: %s)\n", 
                       current_thread, strerror(errno));
            }
            break;
        }
        
        request_count++;
        PRINTF_LOG("İstek alındı (Thread: %lu, İstek #%d, Boyut: %zd bytes)\n", 
               current_thread, request_count, bytes_received);
        
        buffer[bytes_received] = '\0';
        
        // Health check detection - Docker healthcheck'i tespit et
        if (bytes_received == 0 || (bytes_received > 0 && buffer[0] == '\0')) {
            PRINTF_LOG("HEALTHCHECK: Docker health check tespit edildi (Thread: %lu)\n", current_thread);
            fflush(stdout);
            close(client_socket);
            remove_thread_info(current_thread);
            return NULL;
        }
        
        // Boş veya çok kısa mesajları health check olarak değerlendir
        if (bytes_received < 5) {
            PRINTF_LOG("HEALTHCHECK: Kısa mesaj - muhtemelen health check (Thread: %lu, Boyut: %zd)\n", 
                   current_thread, bytes_received);
            fflush(stdout);
            close(client_socket);
            remove_thread_info(current_thread);
            return NULL;
        }
        
        char *current_time = get_current_time();
        PRINTF_LOG("[%s] Mesaj alindi (%zd byte)\n", current_time, bytes_received);
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
        
        PRINTF_LOG("Komut: %s\n", command);
        PRINTF_LOG("Dosya: %s\n", filename);
        fflush(stdout);
        
        char *parsed_result = NULL;
        
        // Komut tipine gore islem yap
        if (strcmp(command, "PARSE") == 0) {
            PRINTF_LOG("Normal JSON parse ediliyor (Tactical Data format)...\n");
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
            PRINTF_LOG("Sifreli JSON parse ediliyor (Tactical Data format)...\n");
            fflush(stdout);
            parsed_result = handle_encrypted_request(filename, content, session_key);
        } else {
            parsed_result = malloc(256);
            snprintf(parsed_result, 256, "HATA: Bilinmeyen komut: %s", command);
        }
        
        // Sonucu client'a gonder
        if (parsed_result != NULL) {
            send(client_socket, parsed_result, strlen(parsed_result), 0);
            PRINTF_LOG("Parse sonucu gonderildi\n");
            fflush(stdout);
            free(parsed_result);
        }
        
        // Bellek temizligi
        free(command);
        free(filename);
        free(content);
    }

    close(client_socket);
    PRINTF_LOG("Client bağlantısı kapatıldı (Thread: %lu, Toplam istek: %d)\n", 
           current_thread, request_count);
    
    // ECDH temizliği
    cleanup_ecdh_for_connection(&client_manager);
    
    // Thread bilgilerini temizle
    remove_thread_info(current_thread);
    
    PRINTF_LOG("✅ Thread slot serbest kaldı - Queue kontrol ediliyor...\n");
    fflush(stdout);
    
    fflush(stdout);
    return NULL; // void* döndürmek için
}

/**
 * @brief Şifreli JSON isteklerini işler ve veritabanına kaydeder
 * @ingroup server
 * 
 * Bu fonksiyon ENCRYPTED protokol komutunu işler. Hex formatındaki
 * şifreli veriyi çözer, JSON'a dönüştürür ve veritabanına kaydeder.
 * 
 * İşlem adımları:
 * 1. Session key geçerliliğini kontrol eder
 * 2. Hex string'i byte array'e çevirir
 * 3. İlk 16 byte'ı IV olarak ayırır
 * 4. AES256 ile veriyi decrypt eder
 * 5. Decrypted JSON'u tactical data'ya parse eder
 * 6. Veritabanına kaydeder ve response üretir
 * 7. Tüm belleği temizler
 * 
 * @param filename İşlem yapılacak dosya adı (log için)
 * @param encrypted_content Hex formatında şifreli veri
 * @param session_key ECDH ile üretilen AES256 session key
 * 
 * @return Başarıda parse sonucu string'i (malloc'lu)
 * @return Hata durumunda hata mesajı (malloc'lu)
 * 
 * @note Döndürülen string caller tarafından free edilmelidir.
 *       Fonksiyon tüm geçici belleği otomatik temizler.
 * 
 * @warning Session key NULL olmamalı, aksi halde hata döner.
 *          Encrypted data en az IV boyutu (16 byte) içermelidir.
 * 
 * Hata durumları:
 * - NULL session key
 * - Geçersiz hex format
 * - Yetersiz veri boyutu (IV eksik)
 * - Decryption başarısızlığı
 * - JSON parse hatası
 * 
 * @see hex_to_bytes()
 * @see decrypt_data()
 * @see parse_json_to_tactical_data()
 * @see db_save_tactical_data_and_get_response()
 */
// Sifreli istek ile bas et
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key) {
    if (session_key == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Session key NULL");
        return error_msg;
    }
    
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
        session_key, // ECDH ile üretilen session key
        iv
    );
    
    free(encrypted_bytes);
    
    if (decrypted_json == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Decryption basarisiz");
        return error_msg;
    }
    
    PRINTF_LOG("Decrypted JSON: %s\n", decrypted_json);
    
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

/**
 * @brief Protokol mesajını parse eder - "COMMAND:FILENAME:CONTENT" formatı
 * @ingroup server
 * 
 * Client'tan gelen protokol mesajını üç parçaya ayırır: komut, dosya adı ve içerik.
 * Sunucu protokolü gereği mesajlar ":" karakteri ile ayrılmış olmalıdır.
 * 
 * Protokol formatı:
 * - PARSE:filename.json:{"unit":"data"}
 * - ENCRYPTED:filename.json:48656c6c6f576f726c64
 * - CONTROL:command_name:parameters
 * 
 * @param message Parse edilecek protokol mesajı
 * @param command Output: Komut string'i (malloc'lu)
 * @param filename Output: Dosya adı string'i (malloc'lu)
 * @param content Output: İçerik string'i (malloc'lu)
 * 
 * @return 0 başarılı parse işlemi
 * @return -1 format hatası veya bellek ayırma hatası
 * 
 * @note Başarılı parse'da tüm output parametreleri malloc'lu string'ler olur.
 *       Caller bu string'leri free etmekle yükümlüdür.
 * 
 * @warning Hata durumunda kısmen ayrılan bellek otomatik temizlenir.
 *          Output parametreleri başarısızlıkta güvenilir değildir.
 * 
 * Örnekler:
 * @code
 * char *cmd, *file, *content;
 * 
 * // Başarılı parse
 * int result = parse_protocol_message("PARSE:data.json:{}", &cmd, &file, &content);
 * if (result == 0) {
 *     // cmd = "PARSE", file = "data.json", content = "{}"
 *     free(cmd); free(file); free(content);
 * }
 * 
 * // Geçersiz format
 * int result = parse_protocol_message("invalid_format", &cmd, &file, &content);
 * // result = -1, output parametreleri güvenilir değil
 * @endcode
 */
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

/**
 * @brief Connection queue'yu işleyen background thread fonksiyonu
 * @ingroup server
 * 
 * Bu thread sürekli çalışarak bekleyen client bağlantılarını kontrol eder.
 * Thread pool dolduğunda queue'da bekleyen client'ları işleme alır.
 * 
 * İşlem döngüsü:
 * 1. Queue'da bekleyen client olup olmadığını kontrol eder
 * 2. Aktif thread sayısının limiti aşıp aşmadığını kontrol eder
 * 3. Her iki koşul sağlanırsa queue'dan client alır
 * 4. Yeni thread oluşturur ve client'ı işleme başlatır
 * 5. Konfigüre edilmiş aralıklarla döngüyü tekrarlar
 * 
 * Kontrol parametreleri:
 * - Queue boyutu: get_queue_size()
 * - Aktif thread sayısı: get_active_thread_count()
 * - Maksimum thread limiti: CONFIG_MAX_CLIENTS
 * - Kontrol aralığı: CONFIG_QUEUE_CHECK_INTERVAL
 * 
 * @param arg Kullanılmayan thread parametresi (NULL)
 * 
 * @return NULL (pthread için void* dönüş)
 * 
 * @note Bu thread sunucu yaşam döngüsü boyunca sürekli çalışır.
 *       Thread oluşturma sonrası kısa bekleme yaparak performansı optimize eder.
 * 
 * @warning Thread infinite loop içinde çalışır, normal şartlarda sonlanmaz.
 *          Sunucu kapatılana kadar aktif kalır.
 * 
 * İstatistik çıktısı:
 * @code
 * 🔄 Queue işleniyor... (Queue: 3, Aktif: 8/10)
 * @endcode
 * 
 * @see get_queue_size()
 * @see get_active_thread_count()
 * @see process_queue()
 */
// Queue processor thread - boş slot olduğunda queue'yu işler
void* queue_processor(void* arg) {
    (void)arg; // unused parameter warning'ini bastır
    
    PRINTF_LOG("Queue processor thread başlatıldı\n");
    fflush(stdout);
    
    while (1) {
        // Queue'da client var mı ve boş thread slot'u var mı kontrol et
        while (get_queue_size() > 0 && get_active_thread_count() < CONFIG_MAX_CLIENTS) {
            PRINTF_LOG("🔄 Queue işleniyor... (Queue: %d, Aktif: %d/%d)\n", 
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


