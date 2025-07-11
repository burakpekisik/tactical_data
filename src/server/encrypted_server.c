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
#include <sys/wait.h>
#include <jwt.h>
#include "crypto_utils.h"
#include "json_utils.h"
#include "database.h"
#include "config.h"
#include "thread_monitor.h"
#include "connection_manager.h"
#include "control_interface.h"
#include "encrypted_server.h"
#include "logger.h"
#include "jwt_manager.h"
#include "report_query_handler.h"
#include "admin_notify_manager.h"
#include "admin_reply_manager.h"
#include "backup_manager.h"
#include "large_response.h"
#include "queue_manager.h"
#include "protocol_parser.h"
#include "handle_manager.h"
#include "pool_manager.h"

// Backup kontrol değişkenleri
volatile int backup_enabled = 1;
volatile int backup_period_seconds = 7200; // Varsayılan: 2 saat

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

    init_chat_pools();
    init_query_pools();
    
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

    // Backup thread'ini başlat
    pthread_t backup_thread;
    pthread_create(&backup_thread, NULL, periodic_backup_thread, NULL);
    pthread_detach(backup_thread);
    
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
    PRINTF_SERVER("Control komutları: start_tcp, stop_tcp, list, stats, backup_on, backup_off, backup_period <saniye>, backup_status, help, quit\n");
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
                } else if (strcmp(command, "backup_on") == 0) {
                    backup_enabled = 1;
                    PRINTF_LOG("✓ Backup periyodik yedekleme AKTİF\n");
                } else if (strcmp(command, "backup_off") == 0) {
                    backup_enabled = 0;
                    PRINTF_LOG("✓ Backup periyodik yedekleme PASİF\n");
                } else if (strncmp(command, "backup_period ", 14) == 0) {
                    int new_period = atoi(command + 14);
                    if (new_period > 0) {
                        backup_period_seconds = new_period;
                        PRINTF_LOG("✓ Backup periyodu güncellendi: %d saniye\n", new_period);
                    } else {
                        PRINTF_LOG("✗ Geçersiz periyot!\n");
                    }
                } else if (strcmp(command, "backup_status") == 0) {
                    PRINTF_LOG("=== BACKUP STATUS ===\nAktif: %s\nPeriyot: %d saniye\n====================\n",
                        backup_enabled ? "EVET" : "HAYIR", backup_period_seconds);
                } else if (strcmp(command, "stop_tcp") == 0) {
                    stop_tcp_server();
                    PRINTF_LOG("✓ TCP Server stopped\n");
                } else if (strcmp(command, "start_tcp") == 0) {
                    if (start_tcp_server(CONFIG_PORT) == 0) {
                        PRINTF_LOG("✓ TCP Server started\n");
                    } else {
                        PRINTF_LOG("✗ TCP Server start failed\n");
                    }
                } else if (strcmp(command, "stop_udp") == 0) {
                    stop_udp_server();
                    PRINTF_LOG("✓ UDP Server stopped\n");
                } else if (strcmp(command, "start_udp") == 0) {
                    if (start_udp_server(CONFIG_UDP_PORT) == 0) {
                        PRINTF_LOG("✓ UDP Server started\n");
                    } else {
                        PRINTF_LOG("✗ UDP Server start failed\n");
                    }
                } else if (strcmp(command, "stop_p2p") == 0) {
                    stop_p2p_node();
                    PRINTF_LOG("✓ P2P Node stopped\n");
                } else if (strcmp(command, "start_p2p") == 0) {
                    if (start_p2p_node(CONFIG_P2P_PORT) == 0) {
                        PRINTF_LOG("✓ P2P Node started\n");
                    } else {
                        PRINTF_LOG("✗ P2P Node start failed\n");
                    }
                } else {
                    PRINTF_LOG("Bilinmeyen komut: %s\n", command);
                    PRINTF_LOG("'help' yazın veya 'quit' ile çıkın\n");
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
        while (true) {
            sleep(10);
            
            // Her 10 saniyede bir stats yazdır
            PRINTF_LOG("=== SERVER STATUS ===\n");
            list_active_connections();
            log_thread_stats();
            PRINTF_LOG("Server aktif, bağlantı bekleniyor... (PID: %d)\n\n", getpid());

            PRINTF_LOG("=== THREAD FUNCTIONS ===\n");
            log_thread_functions();

            fflush(stdout);

        }
    }
    
    PRINTF_LOG("Sunucu kapatılıyor...\n");
    stop_tcp_server();
    db_close();
    admin_notify_manager_cleanup();
    PRINTF_LOG("Server kapatıldı\n");
    return 0;
}

