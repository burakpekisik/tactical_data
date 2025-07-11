/**
 * @file encrypted_client.c
 * @brief Şifreli JSON dosya gönderim istemcisi
 * @details Bu dosya, TCP/UDP/P2P protokolleri kullanarak JSON dosyalarını 
 *          şifreli veya şifresiz olarak sunucuya gönderen istemci uygulamasını içerir.
 *          ECDH anahtar değişimi ve AES256 şifreleme desteği sağlar.
 * @author Ali Burak Pekışık
 * @date 2025
 * @version 1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include "crypto_utils.h"
#include "config.h"
#include "encrypted_client.h"
#include "fallback_manager.h"
#include "protocol_manager.h"
#include "logger.h"
#include "login_user.h"
#include "get_report_list.h"
#include "json_utils.h"
#include "load_balancer.h"
#include "chat_manager.h"
#include "location_manager.h"
#include "info_manager.h"
#include "admin_reply_manager.h"
#include "report_query_manager.h"
#include "listen_manager.h"
#include "thread_manager.h"
 
char jwt_token[1024] = ""; // Global JWT token
static lb_config_t lb_config; // Global load balancer config

struct report_reply_entry report_replies[MAX_REPORT_REPLIES];
int report_reply_count = 0;
pthread_mutex_t report_reply_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * ÖNEMLİ NOT:
 * Bu istemci uygulamasında login (JWT alma) işlemi ve ECDH anahtar değişimi/veri iletimi
 * kesinlikle FARKLI bağlantılar (socket) üzerinden yapılmalıdır.
 * Sunucu, login mesajı sonrası bağlantıyı kapatır ve ECDH için yeni bağlantı bekler.
 * Eğer login sonrası aynı socket ile devam edilirse, ECDH anahtar değişimi sırasında takılma olur.
 *
 * Bu akış bozulursa, client ve server arasında ECDH handshake asla tamamlanamaz!
 */

/**
 * @brief Ana program fonksiyonu
 * @details İstemci uygulamasının ana giriş noktası. Kullanıcı menüsünü gösterir
 *          ve sunucuya bağlantı kurarak JSON dosya gönderim işlemlerini yönetir.
 * @return int Program çıkış kodu (0: başarılı, -1: hata)
 */
int main() {
    char filename[CONFIG_MAX_FILENAME];
    int choice;
    char username[128];
    char password[128];

    // Logger'ı başlat
    if (logger_init(LOGGER_CLIENT, LOG_DEBUG) != 0) {
        fprintf(stderr, "Logger başlatılamadı!\n");
        return -1;
    }

    // Load balancer'ı başlat
    if (lb_init(&lb_config) != 0) {
        fprintf(stderr, "Load balancer başlatılamadı!\n");
        logger_cleanup(LOGGER_CLIENT);
        return -1;
    }

    // Config dosyasından sunucuları yükle (öncelikli)
    // Docker ortamında farklı config kullan
    const char *config_file = "config/servers.conf";
    const char *server_host_env = getenv("SERVER_HOST");
    if (server_host_env && strcmp(server_host_env, "encrypted-server") == 0) {
        // Docker Compose ortamı
        config_file = "config/servers-docker.conf";
        PRINTF_CLIENT("Docker ortamı algılandı, Docker config kullanılıyor...\n");
    }
    
    if (lb_load_config_file(&lb_config, config_file) != 0) {
        PRINTF_CLIENT("Config dosyası yüklenemedi (%s), manuel konfigürasyon kullanılıyor...\n", config_file);
        
        // Manuel konfigürasyon (fallback)
        // Ana nginx load balancer
        const char *nginx_host = getenv("NGINX_HOST");
        if (!nginx_host) nginx_host = "127.0.0.1";
        lb_add_server(&lb_config, nginx_host, 8080, 8081, 8082, 9090, 5, false);
        
        // Gerçek sunucu IP adresleri - Environment variable'lardan
        const char *server_host = getenv("SERVER_HOST");
        if (!server_host) server_host = "127.0.0.1";
        lb_add_server(&lb_config, server_host, 8080, 8081, 8082, 9090, 3, false);
        
        const char *server1_ip = getenv("SERVER1_IP");
        if (!server1_ip) server1_ip = "192.168.1.100";
        lb_add_server(&lb_config, server1_ip, 8080, 8081, 8082, 9090, 3, false);
        
        const char *server2_ip = getenv("SERVER2_IP");
        if (!server2_ip) server2_ip = "192.168.1.101";
        lb_add_server(&lb_config, server2_ip, 8080, 8081, 8082, 9090, 3, false);
        
        const char *server3_ip = getenv("SERVER3_IP");
        if (!server3_ip) server3_ip = "192.168.1.102";
        lb_add_server(&lb_config, server3_ip, 8080, 8081, 8082, 9090, 2, false);
        
        const char *backup_ip = getenv("BACKUP_SERVER_IP");
        if (!backup_ip) backup_ip = "192.168.1.200";
        lb_add_server(&lb_config, backup_ip, 8080, 8081, 8082, 9090, 1, true);
    }
    
    LOG_CLIENT_INFO("Load balancer configured with %d servers", lb_config.server_count);
    
    // İlk sağlık kontrolü
    int healthy_servers = lb_check_all_servers_health(&lb_config);
    if (healthy_servers == 0) {
        PRINTF_CLIENT("Uyarı: Hiç sağlıklı sunucu bulunamadı!\n");
    } else {
        PRINTF_CLIENT("Load balancer hazır: %d/%d sunucu sağlıklı\n", 
                     healthy_servers, lb_config.server_count);
    }

    // Kullanıcıdan login bilgisi al
    PRINTF_CLIENT("Kullanıcı adı: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    PRINTF_CLIENT("Şifre: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    // Sunucuya login isteği gönder (load balancer ile)
    char *token = client_login_to_server_with_lb(&lb_config, username, password);
    if (token == NULL) {
        PRINTF_CLIENT("Giriş başarısız!\n");
        lb_cleanup(&lb_config);
        logger_cleanup(LOGGER_CLIENT);
        return -1;
    }
    strncpy(jwt_token, token, sizeof(jwt_token)-1);
    jwt_token[sizeof(jwt_token)-1] = '\0';
    PRINTF_CLIENT("Giriş başarılı! JWT alındı.\n");
    free(token);
    
    LOG_CLIENT_INFO("Login sonrası yeni bağlantı açılıyor (ECDH için)");
    // Server'a baglan (login sonrası YENİ bağlantı!) - Load balancer ile
    client_connection_t* conn = connect_to_server_with_lb(&lb_config);
    if (conn == NULL) {
        LOG_CLIENT_ERROR("Failed to connect to server");
        lb_cleanup(&lb_config);
        logger_cleanup(LOGGER_CLIENT);
        return -1;
    }

    LOG_CLIENT_INFO("Successfully connected to server");
    PRINTF_CLIENT("Server'a basariyla baglandi\n");
    
    while (1) {
        show_menu();
        PRINTF_LOG("Seciminiz: ");
        if (scanf("%d", &choice) != 1) {
            PRINTF_LOG("Gecersiz secim\n");
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');
        switch (choice) {
            case 1: // Normal JSON gonder
                PRINTF_LOG("JSON dosya adini girin: ");
                if (fgets(filename, CONFIG_MAX_FILENAME, stdin) != NULL) {
                    filename[strcspn(filename, "\n")] = 0; // Newline kaldir
                    if (strlen(filename) > 0) {
                        send_json_file(conn, filename, 0, jwt_token);
                    }
                }
                break;
                
            case 2: // Sifreli JSON gonder
                PRINTF_LOG("JSON dosya adini girin: ");
                if (fgets(filename, CONFIG_MAX_FILENAME, stdin) != NULL) {
                    filename[strcspn(filename, "\n")] = 0;
                    if (strlen(filename) > 0) {
                        send_json_file(conn, filename, 1, jwt_token);
                    }
                }
                break;
                
            case 3: // Sifreli rapor listesi al
                LOG_CLIENT_INFO("Sifreli rapor listesi aliniyor...");
                if (get_report_list_by_user(conn, jwt_token) == 1) {
                    PRINTF_CLIENT("Rapor listesi alindi ve ekrana yazdirildi.\n");
                } else {
                    PRINTF_CLIENT("Rapor listesi alınamadı veya bağlantı hatası!\n");
                }
                break;
            case 4: // Admin bildirimlerini dinle
                listen_for_admin_notifications(conn);
                break;
            case 5: // Admin rapora cevap ver
                if (admin_reply_to_report(conn, jwt_token) != 0) {
                    PRINTF_LOG("Rapor cevabi gonderilemedi!\n");
                } else {
                    PRINTF_LOG("Rapor cevabi basariyla gonderildi.\n");
                }
                break;
            case 6: // Gelen admin cevaplarını görüntüle
                listen_report_replies(conn);
                break;
            case 7: // Kendi reply'larımı JWT ile sorgula
                query_my_replies_with_jwt(conn, jwt_token);
                break;
            case 8: // Reportlarıma gelen cevapları sorgula
                query_my_replies(conn, jwt_token);
                break;
            case 9:
                query_replies_to_one_report(conn, jwt_token);
                break;
            case 10: // Load balancer istatistikleri
                lb_print_stats(&lb_config);
                break;
                
            case 11: // Chat odasi olustur
                if (create_chat_room_interactive(conn, jwt_token) != 0) {
                    PRINTF_CLIENT("Chat odası oluşturulamadı!\n");
                }
                break;
                
            case 12: // Chat odalarini listele ve katil
                if (list_and_join_chat_rooms(conn, jwt_token) != 0) {
                    PRINTF_CLIENT("Chat odalarına erişim başarısız!\n");
                }
                break;
            case 13:
            {
                double latitude = 0.0, longitude = 0.0;
                printf("Lütfen enlem (latitude) değerini girin: ");
                if (scanf("%lf", &latitude) != 1) {
                    PRINTF_CLIENT("Latitude değeri alınamadı!\n");
                    while (getchar() != '\n');
                    break;
                }
                printf("Lütfen boylam (longitude) değerini girin: ");
                if (scanf("%lf", &longitude) != 1) {
                    PRINTF_CLIENT("Longitude değeri alınamadı!\n");
                    while (getchar() != '\n');
                    break;
                }
                while (getchar() != '\n'); // input buffer temizle

                location_t location;
                memset(&location, 0, sizeof(location));
                // Kullanıcı ID'si JWT'den veya başka bir yerden alınmalı, örnek olarak 0 verildi
                location.user_id = 0;
                location.latitude = latitude;
                location.longitude = longitude;
                location.timestamp = time(NULL);

                send_insert_location(conn, &location, jwt_token);
                PRINTF_CLIENT("Konum gönderildi: (%.8f, %.8f)\n", latitude, longitude);
                break;
            }
            case 14:
                send_select_location_of_user(conn, jwt_token);
                break;

            case 15:
                int unit_id;
                printf("Lütfen birim numarası (unit_id) değerini girin: ");
                if (scanf("%d", &unit_id) != 1) {
                    PRINTF_CLIENT("Latitude değeri alınamadı!\n");
                    while (getchar() != '\n');
                    break;
                }
                
                while (getchar() != '\n'); // input buffer temizle

                send_select_latest_locations_by_unit(conn, unit_id, jwt_token);
                break;

            case 16: // Tüm kullanıcıların son konumları
                send_select_latest_locations_all_users(conn, jwt_token);
                break;
            case 17: // Tüm kullanıcları yarıçapa göre seç
                double latitude = 0.0, longitude = 0.0, radius = 0.0;
                printf("Lütfen enlem (latitude) değerini girin: ");
                if (scanf("%lf", &latitude) != 1) {
                    PRINTF_CLIENT("Latitude değeri alınamadı!\n");
                    while (getchar() != '\n');
                    break;
                }
                printf("Lütfen boylam (longitude) değerini girin: ");
                if (scanf("%lf", &longitude) != 1) {
                    PRINTF_CLIENT("Longitude değeri alınamadı!\n");
                    while (getchar() != '\n');
                    break;
                }

                printf("Lütfen arama yarıçapı (radius) değerini girin: ");
                if (scanf("%lf", &radius) != 1) {
                    PRINTF_CLIENT("Yarıçap değeri alınamadı!\n");
                    while (getchar() != '\n');
                    break;
                }
                while (getchar() != '\n'); // input buffer temizle

                send_select_latest_locations_all_users_by_radius(conn, latitude, longitude, radius, jwt_token);
                break;
            case 18:
                send_select_latest_locations_by_current_unit(conn, jwt_token);
                break;
            case 19:
                send_info_message(conn, jwt_token);
                break;
            case 20: // Cikis
            {
                LOG_CLIENT_INFO("User requested shutdown");
                PRINTF_CLIENT("Baglanti kapatiliyor...\n");
                close_connection(conn);
                lb_cleanup(&lb_config);
                LOG_CLIENT_INFO("Connection closed, shutting down client");
                lb_end_sticky_session(&lb_config);
                lb_cleanup(&lb_config);
                logger_cleanup(LOGGER_CLIENT);
                return 0;
            }
            default:
                PRINTF_LOG("Gecersiz secim. Lutfen 1-13 arasi bir sayi girin.\n");
                break;
        }
        PRINTF_LOG("\n");
    }
    
    LOG_CLIENT_INFO("Client shutting down");
    close_connection(conn);
    lb_end_sticky_session(&lb_config);
    lb_cleanup(&lb_config);
    logger_cleanup(LOGGER_CLIENT);
    return 0;
}

/**
 * @brief Kullanıcı menüsünü ekranda gösterir
 * @details Ana menü seçeneklerini formatlanmış şekilde ekrana yazdırır.
 *          Kullanıcı 11 seçenekten birini seçebilir.
 */
void show_menu(void) {
    PRINTF_LOG("\n=== MENU ===\n");
    
    // Sticky session durumunu göster
    if (lb_is_session_active(&lb_config)) {
        server_info_t *assigned_server = lb_get_assigned_server(&lb_config);
        if (assigned_server) {
            PRINTF_LOG("🔒 Sticky Session: %s:%d (Session ID: %s)\n", 
                      assigned_server->host, assigned_server->tcp_port, lb_config.session_id);
        }
    } else {
        PRINTF_LOG("🔓 Sticky Session: Henüz bağlantı kurulmamış\n");
    }
    
    PRINTF_LOG("1. Normal JSON dosyasi gonder\n");
    PRINTF_LOG("2. Sifreli JSON dosyasi gonder\n");
    PRINTF_LOG("3. Rapor listesini al\n");
    PRINTF_LOG("4. Admin bildirimlerini dinle (admin için)\n");
    PRINTF_LOG("5. Raporlara cevap ver (admin)\n");
    PRINTF_LOG("6. Gelen admin cevaplarını görüntüle\n");
    PRINTF_LOG("7. Kendi reply'larımı JWT ile sorgula\n");
    PRINTF_LOG("8. Reportlarıma gelen cevapları sorgula\n");
    PRINTF_LOG("9. Bir rapora gelen cevapları sorgula\n");
    PRINTF_LOG("10. Load balancer istatistikleri\n");
    PRINTF_LOG("11. Chat odasi olustur\n");
    PRINTF_LOG("12. Chat odalarini listele ve katil\n");
    PRINTF_LOG("13. Lokasyon bilgisi gonder\n");
    PRINTF_LOG("14. Kullanici konumunu al\n");
    PRINTF_LOG("15. Unit ID'ye ait birimlerin konumunu al\n");
    PRINTF_LOG("16. Tüm kullanıcıların son konumları\n");
    PRINTF_LOG("17. Kullanıcıları çap göre seç\n");
    PRINTF_LOG("18. Birliğime ait son konumları al\n");
    PRINTF_LOG("19. Bilgi mesajı gönder\n");
    PRINTF_LOG("20. Cikis\n");
    PRINTF_LOG("================\n");
}

/**
 * @brief Sunucu yanıtını alır ve işler
 * @details Aktif bağlantı türüne göre (TCP/UDP/P2P) sunucudan gelen
 *          yanıt mesajını alır ve formatlanmış şekilde ekrana yazdırır.
 * @param conn Aktif sunucu bağlantısı
 * @note Yanıt alınamazsa veya bağlantı kesilirse uygun hata mesajları gösterilir
 */
void handle_server_response(client_connection_t* conn) {
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    
    ssize_t bytes_received;
    if (conn->type == CONN_TYPE_TCP) {
        bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    } else if (conn->type == CONN_TYPE_UDP) {
        bytes_received = receive_udp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    } else if (conn->type == CONN_TYPE_P2P) {
        bytes_received = receive_p2p_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    } else {
        PRINTF_LOG("Bilinmeyen baglanti tipi yanit alinamadi\n");
        return;
    }
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        PRINTF_LOG("\nServer yaniti:\n");
        PRINTF_LOG("=============\n");
        PRINTF_LOG("%s\n", buffer);
        PRINTF_LOG("=============\n");
    } else if (bytes_received == 0) {
        PRINTF_LOG("Server baglantisi kapatildi\n");
    } else {
        PRINTF_LOG("Yanitlama hatasi\n");
    }
}

/**
 * @brief Sunucuya bağlantı kurar
 * @details Verilen sunucu adresine sırasıyla TCP, UDP ve P2P protokolleri
 *          ile bağlantı kurmaya çalışır. Her protokol için ECDH anahtar 
 *          değişimi gerçekleştirir ve AES256 oturum anahtarı oluşturur.
 * @param server_host Sunucu IP adresi veya hostname (NULL ise 127.0.0.1 kullanılır)
 * @return client_connection_t* Bağlantı yapısı (NULL: başarısız)
 * @note Bağlantı öncelik sırası: TCP (8080) -> UDP (8081) -> P2P (8082)
 * @warning Dönen yapı kullanım sonrasında close_connection() ile kapatılmalıdır
 */
client_connection_t* connect_to_server(const char* server_host) {
    client_connection_t* conn = malloc(sizeof(client_connection_t));
    if (conn == NULL) {
        LOG_CLIENT_ERROR("Memory allocation failed for connection");
        PRINTF_LOG("Bellek tahsis hatasi\n");
        return NULL;
    }
    
    // Connection struct'i başlat
    memset(conn, 0, sizeof(client_connection_t));
    
    if (server_host == NULL) {
        server_host = "127.0.0.1";
    }
    
    LOG_CLIENT_INFO("Attempting to connect to server: %s", server_host);
    PRINTF_CLIENT("Server'a baglaniliyor: %s\n", server_host);
    
    /* ========================================
     * TCP Bağlantısı Denemesi (Port: 8080)
     * ======================================== */
    LOG_CLIENT_DEBUG("Trying TCP connection (Port: %d)...", CONFIG_PORT);
    PRINTF_CLIENT("TCP baglantisi deneniyor (Port: %d)...\n", CONFIG_PORT);
    conn->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->socket >= 0) {
        // SO_LINGER ayarı: bağlantı kapatılırken veri hemen gönderilsin
        struct linger so_linger = {1, 0};
        setsockopt(conn->socket, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));
        
        conn->server_addr.sin_family = AF_INET;
        conn->server_addr.sin_port = htons(CONFIG_PORT);
        conn->port = CONFIG_PORT;
        conn->type = CONN_TYPE_TCP;
        
        // IP adresini çözümle
        if (inet_pton(AF_INET, server_host, &conn->server_addr.sin_addr) <= 0) {
            LOG_CLIENT_DEBUG("Resolving hostname: %s", server_host);
            struct hostent *host_entry = gethostbyname(server_host);
            if (host_entry != NULL) {
                conn->server_addr.sin_addr = *((struct in_addr*)host_entry->h_addr_list[0]);
            } else {
                PRINTF_LOG("Host cozumlenemedi: %s\n", server_host);
                close(conn->socket);
                goto try_udp;
            }
        }
        
        // Socket'i non-blocking yaparak timeout ekleyelim
        int flags = fcntl(conn->socket, F_GETFL, 0);
        fcntl(conn->socket, F_SETFL, flags | O_NONBLOCK);
        
        // TCP baglantisi dene (non-blocking)
        int connect_result = connect(conn->socket, (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr));
        
        if (connect_result == 0) {
            // Anında bağlandı
            fcntl(conn->socket, F_SETFL, flags); // Socket'i tekrar blocking yap
            PRINTF_LOG("✓ TCP baglantisi basarili (Port: %d)\n", CONFIG_PORT);
        } else if (errno == EINPROGRESS) {
            // Bağlantı devam ediyor, timeout ile bekle
            fd_set write_fds;
            struct timeval timeout;
            
            FD_ZERO(&write_fds);
            FD_SET(conn->socket, &write_fds);
            
            timeout.tv_sec = 3;  // 3 saniye timeout
            timeout.tv_usec = 0;
            
            int select_result = select(conn->socket + 1, NULL, &write_fds, NULL, &timeout);
            
            if (select_result > 0) {
                // Bağlantı durumu kontrol et
                int sock_error;
                socklen_t len = sizeof(sock_error);
                getsockopt(conn->socket, SOL_SOCKET, SO_ERROR, &sock_error, &len);
                
                if (sock_error == 0) {
                    // Başarılı bağlantı
                    fcntl(conn->socket, F_SETFL, flags); // Socket'i tekrar blocking yap
                    PRINTF_LOG("✓ TCP baglantisi basarili (Port: %d)\n", CONFIG_PORT);
                } else {
                    // Bağlantı hatası
                    PRINTF_LOG("✗ TCP baglantisi basarisiz (Port: %d): %s\n", CONFIG_PORT, strerror(sock_error));
                    close(conn->socket);
                    goto try_udp;
                }
            } else if (select_result == 0) {
                // Timeout
                PRINTF_LOG("✗ TCP baglantisi timeout (Port: %d)\n", CONFIG_PORT);
                close(conn->socket);
                goto try_udp;
            } else {
                // Select hatası
                PRINTF_LOG("✗ TCP baglantisi select hatasi (Port: %d)\n", CONFIG_PORT);
                close(conn->socket);
                goto try_udp;
            }
        } else {
            // Anında hata
            PRINTF_LOG("✗ TCP baglantisi basarisiz (Port: %d): %s\n", CONFIG_PORT, strerror(errno));
            close(conn->socket);
            goto try_udp;
        }
        
        // TCP bağlantısı başarılı, ECDH anahtar değişimi yap
        // Bu noktaya geldiyse bağlantı kesinlikle başarılı
        PRINTF_LOG("✓ TCP baglantisi basarili (Port: %d)\n", CONFIG_PORT);
        
        /* TCP için ECDH Anahtar Değişimi */
        if (!ecdh_init_context(&conn->ecdh_ctx)) {
            PRINTF_LOG("ECDH context başlatılamadı\n");
            close(conn->socket);
            free(conn);
            return NULL;
        }
            
            if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
                PRINTF_LOG("ECDH anahtar çifti üretilemedi\n");
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Server ile anahtar değişimi
            PRINTF_LOG("Server ile anahtar değişimi yapılıyor...\n");
            
            // Kendi public key'imizi gönder
            PRINTF_LOG("Kendi public key gönderiliyor...\n");
            ssize_t sent = send(conn->socket, conn->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
            if (sent != ECC_PUB_KEY_SIZE) {
                perror("Client public key send hatası");
                PRINTF_LOG("Public key gönderilemedi, sent=%zd\n", sent);
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            PRINTF_LOG("Kendi public key gönderildi, sent=%zd\n", sent);
            PRINTF_LOG("Server public key bekleniyor...\n");
            uint8_t server_public_key[ECC_PUB_KEY_SIZE];
            ssize_t received = recv(conn->socket, server_public_key, ECC_PUB_KEY_SIZE, 0);
            PRINTF_LOG("Server public key alındı, received=%zd\n", received);
            if (received != ECC_PUB_KEY_SIZE) {
                PRINTF_LOG("Server public key alınamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Shared secret hesapla
            if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
                PRINTF_LOG("Shared secret hesaplanamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // AES anahtarını türet
            if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
                PRINTF_LOG("AES anahtarı türetilemedi\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            conn->ecdh_initialized = true;
            PRINTF_LOG("✓ ECDH anahtar değişimi tamamlandı\n");
            PRINTF_LOG("✓ AES256 oturum anahtarı hazır\n");
            
            // ECDH sonrası sunucuya HELLO mesajı gönder
            if (send_hello_after_ecdh(conn, jwt_token) != 0) {
                PRINTF_LOG("ECDH sonrası HELLO mesajı gönderilemedi!\n");
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            return conn;
    }
    
try_udp:
    /* ========================================
     * UDP Bağlantısı Denemesi (Port: 8081)
     * ======================================== */
    PRINTF_LOG("UDP baglantisi deneniyor (Port: %d)...\n", CONFIG_UDP_PORT);
    conn->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn->socket >= 0) {
        conn->server_addr.sin_family = AF_INET;
        conn->server_addr.sin_port = htons(CONFIG_UDP_PORT);
        conn->port = CONFIG_UDP_PORT;
        conn->type = CONN_TYPE_UDP;
        
        // IP adresini çözümle (UDP için)
        if (inet_pton(AF_INET, server_host, &conn->server_addr.sin_addr) <= 0) {
            struct hostent *host_entry = gethostbyname(server_host);
            if (host_entry != NULL) {
                conn->server_addr.sin_addr = *((struct in_addr*)host_entry->h_addr_list[0]);
            } else {
                PRINTF_LOG("Host cozumlenemedi: %s\n", server_host);
                close(conn->socket);
                goto try_p2p;
            }
        }
        
        // UDP için test ping gönder
        const char* test_msg = "PING";
        if (sendto(conn->socket, test_msg, strlen(test_msg), 0,
                   (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) > 0) {
            // Kısa timeout ile response bekle
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            setsockopt(conn->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            
            char test_buffer[64];
            if (recvfrom(conn->socket, test_buffer, sizeof(test_buffer) - 1, 0, NULL, 0) > 0) {
                PRINTF_LOG("✓ UDP baglantisi basarili (Port: %d)\n", CONFIG_UDP_PORT);
                
                /* UDP için ECDH Anahtar Değişimi */
                if (!ecdh_init_context(&conn->ecdh_ctx)) {
                    PRINTF_LOG("UDP ECDH context başlatılamadı\n");
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
                    PRINTF_LOG("UDP ECDH anahtar çifti üretilemedi\n");
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Server ile UDP ECDH anahtar değişimi
                PRINTF_LOG("UDP Server ile anahtar değişimi yapılıyor...\n");
                
                // ECDH init mesajı gönder
                const char* ecdh_init = "ECDH_INIT";
                if (sendto(conn->socket, ecdh_init, strlen(ecdh_init), 0,
                          (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) < 0) {
                    PRINTF_LOG("UDP ECDH init mesajı gönderilemedi\n");
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Server'in public key'ini bekle
                char server_response[1024];
                ssize_t received = recvfrom(conn->socket, server_response, sizeof(server_response) - 1, 0, NULL, 0);
                if (received < 0) {
                    PRINTF_LOG("UDP Server public key alınamadı\n");
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                server_response[received] = '\0';
                
                // "ECDH_PUB:" prefix'ini kontrol et
                if (strncmp(server_response, "ECDH_PUB:", 9) != 0) {
                    PRINTF_LOG("UDP Geçersiz server response: %s\n", server_response);
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Server public key'ini decode et
                size_t server_key_len;
                uint8_t* server_public_key = hex_to_bytes(server_response + 9, &server_key_len);
                if (server_public_key == NULL || server_key_len != ECC_PUB_KEY_SIZE) {
                    PRINTF_LOG("UDP Server public key decode hatası\n");
                    if (server_public_key) free(server_public_key);
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Kendi public key'imizi gönder
                char client_pub_msg[ECC_PUB_KEY_SIZE * 2 + 20];
                strcpy(client_pub_msg, "ECDH_PUB:");
                char* hex_key = bytes_to_hex(conn->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE);
                if (hex_key) {
                    strcat(client_pub_msg, hex_key);
                    free(hex_key);
                }
                
                if (sendto(conn->socket, client_pub_msg, strlen(client_pub_msg), 0,
                          (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) < 0) {
                    PRINTF_LOG("UDP Client public key gönderilemedi\n");
                    free(server_public_key);
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Shared secret hesapla
                if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
                    PRINTF_LOG("UDP Shared secret hesaplanamadı\n");
                    free(server_public_key);
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // AES anahtarını türet
                if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
                    PRINTF_LOG("UDP AES anahtarı türetilemedi\n");
                    free(server_public_key);
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                free(server_public_key);
                
                // Onay mesajını bekle
                char ack_buffer[64];
                ssize_t ack_received = recvfrom(conn->socket, ack_buffer, sizeof(ack_buffer) - 1, 0, NULL, 0);
                if (ack_received > 0) {
                    ack_buffer[ack_received] = '\0';
                    if (strcmp(ack_buffer, "ECDH_OK") == 0) {
                        conn->ecdh_initialized = true;
                        PRINTF_LOG("✓ UDP ECDH anahtar değişimi tamamlandı\n");
                        PRINTF_LOG("✓ UDP AES256 oturum anahtarı hazır\n");
                        return conn;
                    }
                }
                
                PRINTF_LOG("UDP ECDH onay mesajı alınamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
        }
        
        PRINTF_LOG("✗ UDP baglantisi basarisiz (Port: %d)\n", CONFIG_UDP_PORT);
        close(conn->socket);
    }

try_p2p:
    /* ========================================
     * P2P Bağlantısı Denemesi (Port: 8082)
     * ======================================== */
    PRINTF_LOG("P2P baglantisi deneniyor (Port: %d)...\n", CONFIG_P2P_PORT);
    conn->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->socket >= 0) {
        conn->server_addr.sin_family = AF_INET;
        conn->server_addr.sin_port = htons(CONFIG_P2P_PORT);  
        conn->port = CONFIG_P2P_PORT;
        conn->type = CONN_TYPE_P2P;
        
        // IP adresini çözümle
        if (inet_pton(AF_INET, server_host, &conn->server_addr.sin_addr) <= 0) {
            struct hostent *host_entry = gethostbyname(server_host);
            if (host_entry != NULL) {
                conn->server_addr.sin_addr = *((struct in_addr*)host_entry->h_addr_list[0]);
            } else {
                PRINTF_LOG("Host cozumlenemedi: %s\n", server_host);
                close(conn->socket);
                free(conn);
                return NULL;
            }
        }
        
        // P2P TCP baglantisi dene - Non-blocking ile timeout
        int flags = fcntl(conn->socket, F_GETFL, 0);
        fcntl(conn->socket, F_SETFL, flags | O_NONBLOCK);
        
        int connect_result = connect(conn->socket, (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr));
        if (connect_result == 0) {
            // Anında bağlandı
            fcntl(conn->socket, F_SETFL, flags); // Blocking mode'a geri dön
            PRINTF_LOG("✓ P2P baglantisi basarili (Port: %d)\n", CONFIG_P2P_PORT);
        } else if (errno == EINPROGRESS) {
            // Bağlantı devam ediyor, select ile bekle
            fd_set write_fds;
            struct timeval timeout;
            FD_ZERO(&write_fds);
            FD_SET(conn->socket, &write_fds);
            timeout.tv_sec = 5;  // 5 saniye timeout
            timeout.tv_usec = 0;
            
            int select_result = select(conn->socket + 1, NULL, &write_fds, NULL, &timeout);
            if (select_result > 0) {
                // Bağlantı tamamlandı, hata kontrolü yap
                int error = 0;
                socklen_t error_len = sizeof(error);
                getsockopt(conn->socket, SOL_SOCKET, SO_ERROR, &error, &error_len);
                
                if (error == 0) {
                    fcntl(conn->socket, F_SETFL, flags); // Blocking mode'a geri dön
                    PRINTF_LOG("✓ P2P baglantisi basarili (Port: %d)\n", CONFIG_P2P_PORT);
                } else {
                    PRINTF_LOG("✗ P2P baglantisi hatasi (Port: %d): %s\n", CONFIG_P2P_PORT, strerror(error));
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
            } else {
                PRINTF_LOG("✗ P2P baglantisi timeout (Port: %d)\n", CONFIG_P2P_PORT);
                close(conn->socket);
                free(conn);
                return NULL;
            }
        } else {
            PRINTF_LOG("✗ P2P baglantisi basarisiz (Port: %d): %s\n", CONFIG_P2P_PORT, strerror(errno));
            close(conn->socket);
            free(conn);
            return NULL;
        }
        
        if (true) { // Bağlantı başarılı ise ECDH'ye geç
            
            /* P2P için ECDH Anahtar Değişimi (TCP benzeri) */
            if (!ecdh_init_context(&conn->ecdh_ctx)) {
                PRINTF_LOG("P2P ECDH context başlatılamadı\n");
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
                PRINTF_LOG("P2P ECDH anahtar çifti üretilemedi\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Server ile P2P ECDH anahtar değişimi
            PRINTF_LOG("P2P Server ile anahtar değişimi yapılıyor...\n");
            
            // Kendi public key'imizi gönder
            PRINTF_LOG("Kendi public key gönderiliyor...\n");
            ssize_t sent = send(conn->socket, conn->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
            if (sent != ECC_PUB_KEY_SIZE) {
                perror("Client public key send hatası");
                PRINTF_LOG("Public key gönderilemedi, sent=%zd\n", sent);
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            PRINTF_LOG("Kendi public key gönderildi, sent=%zd\n", sent);
            PRINTF_LOG("Server public key bekleniyor...\n");
            uint8_t server_public_key[ECC_PUB_KEY_SIZE];
            ssize_t received = recv(conn->socket, server_public_key, ECC_PUB_KEY_SIZE, 0);
            PRINTF_LOG("Server public key alındı, received=%zd\n", received);
            if (received != ECC_PUB_KEY_SIZE) {
                PRINTF_LOG("Server public key alınamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Shared secret hesapla
            if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
                PRINTF_LOG("P2P Shared secret hesaplanamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // AES anahtarını türet
            if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
                PRINTF_LOG("P2P AES anahtarı türetilemedi\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            conn->ecdh_initialized = true;
            PRINTF_LOG("✓ P2P ECDH anahtar değişimi tamamlandı\n");
            PRINTF_LOG("✓ P2P AES256 oturum anahtarı hazır\n");
            
            return conn;
        } else {
            PRINTF_LOG("✗ P2P baglantisi basarisiz (Port: %d)\n", CONFIG_P2P_PORT);
            close(conn->socket);
        }
    }
    
    /* Tüm protokoller başarısız */
    PRINTF_LOG("✗ Hicbir protokol ile baglanti kurulamadi!\n");
    free(conn);
    return NULL;
}

/**
 * @brief ECDH sonrası sunucuya HELLO mesajı gönder
 * @details ECDH anahtar değişimi tamamlandıktan sonra, istemci tarafından sunucuya
 *          bir HELLO mesajı gönderilir. Bu mesaj, JWT token'ı içerir ve sunucuya
 *          bağlantının devam ettiğini bildirir.
 * @param conn Aktif sunucu bağlantısı
 * @param jwt_token Kullanıcının JWT token'ı
 * @return int Mesaj gönderimi sonucu (0: başarılı, -1: hata)
 */
int send_hello_after_ecdh(client_connection_t* conn, const char* jwt_token) {
    char hello_msg[1200];
    snprintf(hello_msg, sizeof(hello_msg), "HELLO:%s", jwt_token);
    ssize_t sent = send(conn->socket, hello_msg, strlen(hello_msg), 0);
    if (sent <= 0) {
        PRINTF_LOG("HELLO mesajı gönderilemedi!\n");
        return -1;
    }
    PRINTF_LOG("HELLO mesajı gönderildi (sent=%zd)\n", sent);
    return 0;
}

