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
#include "crypto_utils.h"
#include "config.h"
#include "encrypted_client.h"
#include "fallback_manager.h"
#include "protocol_manager.h"
#include "logger.h"
#include "login_user.h"
#include "get_report_list.h"
#include "json_utils.h"
 
char jwt_token[1024] = ""; // Global JWT token

static struct report_reply_entry report_replies[MAX_REPORT_REPLIES];
static int report_reply_count = 0;
static pthread_mutex_t report_reply_mutex = PTHREAD_MUTEX_INITIALIZER;

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

    // Kullanıcıdan login bilgisi al
    PRINTF_CLIENT("Kullanıcı adı: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    PRINTF_CLIENT("Şifre: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    // Sunucuya login isteği gönder
    char *token = client_login_to_server(username, password);
    if (token == NULL) {
        PRINTF_CLIENT("Giriş başarısız!\n");
        logger_cleanup(LOGGER_CLIENT);
        return -1;
    }
    strncpy(jwt_token, token, sizeof(jwt_token)-1);
    jwt_token[sizeof(jwt_token)-1] = '\0';
    PRINTF_CLIENT("Giriş başarılı! JWT alındı.\n");
    free(token);
    LOG_CLIENT_INFO("Login sonrası yeni bağlantı açılıyor (ECDH için)");
    // Server'a baglan (login sonrası YENİ bağlantı!)
    client_connection_t* conn = connect_to_server(getenv("SERVER_HOST"));
    if (conn == NULL) {
        LOG_CLIENT_ERROR("Failed to connect to server");
        logger_cleanup(LOGGER_CLIENT);
        return -1;
    }
    // --- Kullanıcı için report reply dinleyici thread başlat ---
    // pthread_t reply_thread;
    // pthread_create(&reply_thread, NULL, report_reply_listener_thread, conn);
    // pthread_detach(reply_thread);
    // --- Admin için reply input thread başlat (isteğe bağlı, menüye girmeden de çalışır) ---
    // pthread_t admin_input_thread;
    // pthread_create(&admin_input_thread, NULL, admin_reply_input_thread, conn);
    // pthread_detach(admin_input_thread);
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
                watch_report_replies(conn);
                break;
            case 7: // Kendi reply'larımı JWT ile sorgula
                query_my_replies_with_jwt(conn, jwt_token);
                break;
            case 8: // Reportlarıma gelen cevapları sorgula
                query_my_replies(conn, jwt_token);
                break;
            case 9: // Cikis
            {
                LOG_CLIENT_INFO("User requested shutdown");
                PRINTF_CLIENT("Baglanti kapatiliyor...\n");
                close_connection(conn);
                LOG_CLIENT_INFO("Connection closed, shutting down client");
                logger_cleanup(LOGGER_CLIENT);
                return 0;
            }
            default:
                PRINTF_LOG("Gecersiz secim. Lutfen 1-8 arasi bir sayi girin.\n");
                break;
        }
        PRINTF_LOG("\n");
    }
    
    LOG_CLIENT_INFO("Client shutting down");
    close_connection(conn);
    logger_cleanup(LOGGER_CLIENT);
    return 0;
}

/**
 * @brief Kullanıcı menüsünü ekranda gösterir
 * @details Ana menü seçeneklerini formatlanmış şekilde ekrana yazdırır.
 *          Kullanıcı 3 seçenekten birini seçebilir:
 *          1. Normal JSON dosyası gönder
 *          2. Şifreli JSON dosyası gönder  
 *          3. Çıkış
 */
void show_menu(void) {
    PRINTF_LOG("\n=== MENU ===\n");
    PRINTF_LOG("1. Normal JSON dosyasi gonder\n");
    PRINTF_LOG("2. Sifreli JSON dosyasi gonder\n");
    PRINTF_LOG("3. Rapor listesini al\n");
    PRINTF_LOG("4. Admin bildirimlerini dinle (admin için)\n");
    PRINTF_LOG("5. Raporlara cevap ver (admin)\n");
    PRINTF_LOG("6. Gelen admin cevaplarını görüntüle\n");
    PRINTF_LOG("7. Kendi cevaplarımı sorgula (JWT ile)\n");
    PRINTF_LOG("8. Reportlarıma gelen cevapları sorgula\n");
    PRINTF_LOG("9. Cikis\n");
    PRINTF_LOG("============\n");
}

/**
 * @brief Dosya içeriğini belleğe okur
 * @details Belirtilen dosyayı açar, boyutunu hesaplar ve tüm içeriğini
 *          belleğe yükler. Bellek tahsisi otomatik olarak yapılır.
 * @param filename Okunacak dosyanın adı/yolu
 * @param file_size [OUT] Okunan dosyanın boyutu (byte cinsinden)
 * @return char* Dosya içeriğini içeren bellek adresi (NULL: hata durumunda)
 * @note Dönen bellek alanı çağıran tarafından free() ile serbest bırakılmalıdır
 */
char* read_file_content(const char* filename, size_t* file_size) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        PRINTF_LOG("Dosya acilamadi: %s\n", filename);
        return NULL;
    }
    
    // Dosya boyutunu al
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Bellek tahsis et
    char *content = malloc(*file_size + 1);
    if (content == NULL) {
        PRINTF_LOG("Bellek tahsis hatasi\n");
        fclose(file);
        return NULL;
    }
    
    // Dosyayi oku
    size_t bytes_read = fread(content, 1, *file_size, file);
    content[bytes_read] = '\0';
    fclose(file);
    
    return content;
}

/**
 * @brief JSON dosyasını sunucuya gönderir
 * @details Belirtilen JSON dosyasını okur ve protokol mesajı formatında
 *          sunucuya gönderir. Şifreleme seçeneği mevcuttur.
 * @param conn Aktif sunucu bağlantısı
 * @param filename Gönderilecek JSON dosyasının adı/yolu
 * @param encrypt Şifreleme durumu (1: şifreli, 0: normal)
 * @return int İşlem sonucu (0: başarılı, -1: hata)
 * @note Şifreli gönderim için ECDH anahtar değişiminin tamamlanmış olması gerekir
 */
int send_json_file(client_connection_t* conn, const char* filename, int encrypt, const char* jwt_token) {
    size_t file_size;
    char *content = read_file_content(filename, &file_size);
    if (content == NULL) {
        return -1;
    }
    PRINTF_LOG("Dosya okundu: %s (%zu byte)\n", filename, file_size);
    char *protocol_message;
    if (encrypt) {
        PRINTF_LOG("Sifreleme islemi baslatiliyor...\n");
        if (!conn->ecdh_initialized) {
            PRINTF_LOG("ECDH başlatılmamış - şifreleme yapılamaz\n");
            free(content);
            return -1;
        }
        protocol_message = create_encrypted_protocol_message(filename, content, conn->ecdh_ctx.aes_key, jwt_token);
    } else {
        PRINTF_LOG("Normal gonderim hazırlaniyor...\n");
        protocol_message = create_normal_protocol_message(filename, content, jwt_token);
    }
    if (protocol_message == NULL) {
        free(content);
        return -1;
    }
    PRINTF_LOG("Server'a gonderiliyor...\n");
    int result = try_send_message_current_connection(conn, protocol_message);
    if (result < 0 && encrypt) {
        PRINTF_LOG("Mevcut bağlantı türü (%s) ile gönderim başarısız, UDP fallback deneniyor...\n", get_connection_type_name(conn->type));
        result = send_json_file_udp_fallback(conn, filename, content, jwt_token);
    }
    if (result < 0 && encrypt) {
        PRINTF_LOG("UDP fallback başarısız, P2P fallback deneniyor...\n");
        result = send_json_file_p2p_fallback(conn, filename, content, jwt_token);
    }
    if (result < 0) {
        PRINTF_LOG("Tüm fallback metodları başarısız\n");
        free(content);
        free(protocol_message);
        return -1;
    }
    PRINTF_LOG("Basariyla gonderildi\n");
    free(content);
    free(protocol_message);
    return 0;
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
        
        // TCP baglantisi dene
        if (connect(conn->socket, (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) == 0) {
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
        } else {
            PRINTF_LOG("✗ TCP baglantisi basarisiz (Port: %d)\n", CONFIG_PORT);
            close(conn->socket);
        }
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
        
        // P2P TCP baglantisi dene
        if (connect(conn->socket, (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) == 0) {
            PRINTF_LOG("✓ P2P baglantisi basarili (Port: %d)\n", CONFIG_P2P_PORT);
            
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

void add_report_reply(int report_id, const char* msg) {
    pthread_mutex_lock(&report_reply_mutex);
    printf("[CLIENT][add_report_reply] Çağrıldı: report_id=%d, msg=%s\n", report_id, msg);
    if (report_reply_count < MAX_REPORT_REPLIES) {
        report_replies[report_reply_count].report_id = report_id;
        strncpy(report_replies[report_reply_count].msg, msg, sizeof(report_replies[report_reply_count].msg)-1);
        report_replies[report_reply_count].msg[sizeof(report_replies[report_reply_count].msg)-1] = '\0';
        report_reply_count++;
        printf("[CLIENT][add_report_reply] Eklendi. Toplam cevap: %d\n", report_reply_count);
    } else {
        printf("[CLIENT][add_report_reply] HATA: MAX_REPORT_REPLIES aşıldı!\n");
    }
    pthread_mutex_unlock(&report_reply_mutex);
}

void show_report_replies(void) {
    pthread_mutex_lock(&report_reply_mutex);
    printf("[CLIENT][show_report_replies] Çağrıldı. Toplam cevap: %d\n", report_reply_count);
    if (report_reply_count == 0) {
        printf("\nHenüz admin cevabı yok.\n");
    } else {
        printf("\nGelen admin cevapları:\n");
        for (int i = 0; i < report_reply_count; ++i) {
            printf("- Rapor #%d: %s\n", report_replies[i].report_id, report_replies[i].msg);
        }
    }
    pthread_mutex_unlock(&report_reply_mutex);
}

void* report_reply_listener_thread(void* arg) {
    client_connection_t* conn = (client_connection_t*)arg;
    char buffer[4096];
    printf("[CLIENT][report_reply_listener_thread] Başlatıldı.\n");
    while (1) {
        ssize_t n = recv(conn->socket, buffer, sizeof(buffer)-1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            printf("[CLIENT][report_reply_listener_thread] Mesaj alındı: %s\n", buffer);
            if (strncmp(buffer, "REPORT_REPLY:", 13) == 0) {
                char* p = buffer + 13;
                int report_id = atoi(p);
                char* msg = strchr(p, ':');
                if (msg) msg++;
                else msg = "";
                add_report_reply(report_id, msg);
            }
        } else {
            printf("[CLIENT][report_reply_listener_thread] recv döngüsü kırıldı. n=%zd\n", n);
            break;
        }
    }
    return NULL;
}

// Admin için: terminalden komut alıp reply gönder
void* admin_reply_input_thread(void* arg) {
    client_connection_t* conn = (client_connection_t*)arg;
    while (1) {
        printf("Admin reply için: REPLY_REPORT <report_id> <mesaj>\n> ");
        char line[1024];
        if (!fgets(line, sizeof(line), stdin)) break;
        int report_id;
        char msg[900];
        if (sscanf(line, "REPLY_REPORT %d %[\n]", &report_id, msg) == 2) {
            char cmd[1200];
            snprintf(cmd, sizeof(cmd), "REPLY_REPORT:%d:%s", report_id, msg);
            send(conn->socket, cmd, strlen(cmd), 0);
        }
    }
    return NULL;
}

void listen_for_admin_notifications(client_connection_t* conn) {
    extern char jwt_token[];
    char notify_cmd[2048];
    snprintf(notify_cmd, sizeof(notify_cmd), "ADMIN_NOTIFY_LISTEN:%s", jwt_token);
    send(conn->socket, notify_cmd, strlen(notify_cmd), 0);

    char buffer[4096];
    printf("\n[ADMIN] Bildirim dinleme başlatıldı. Sunucudan gelen bildirimler burada gösterilecek.\nÇıkmak için Ctrl+C kullanabilirsiniz.\n\n");
    while (1) {
        ssize_t n = recv(conn->socket, buffer, sizeof(buffer)-1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            printf("\n[ADMIN BILDIRIM] Sunucudan gelen bildirim:\n%s\n", buffer);
        } else if (n == 0) {
            printf("\n[ADMIN] Sunucu bağlantısı kapatıldı.\n");
            break;
        } else {
            perror("[ADMIN] Bildirim okuma hatası");
            break;
        }
    }
}

void watch_report_replies(client_connection_t* conn) {
    pthread_t reply_thread;
    pthread_create(&reply_thread, NULL, report_reply_listener_thread, conn);
    pthread_detach(reply_thread);
    int last_count = 0;
    printf("\nGelen admin cevaplarını izleme modunda. Çıkmak için Ctrl+C kullanabilirsiniz.\n");
    while (1) {
        pthread_mutex_lock(&report_reply_mutex);
        if (report_reply_count > last_count) {
            for (int i = last_count; i < report_reply_count; ++i) {
                printf("- Rapor #%d: %s\n", report_replies[i].report_id, report_replies[i].msg);
            }
            last_count = report_reply_count;
        }
        pthread_mutex_unlock(&report_reply_mutex);
        sleep(1); // 1 saniye bekle
    }
}

// Kullanıcının kendi reply'larını JWT ile sorgulayan fonksiyon
void query_my_replies_with_jwt(client_connection_t* conn, const char* jwt_token) {
    if (!conn || !jwt_token || strlen(jwt_token) == 0) {
        PRINTF_CLIENT("JWT token veya bağlantı hatalı!\n");
        return;
    }
    if (!conn->ecdh_initialized) {
        PRINTF_CLIENT("ECDH başlatılmamış - şifreli sorgu yapılamaz!\n");
        return;
    }
    
    PRINTF_LOG("[CLIENT][REPLY_QUERY] JWT ile reply sorgulama başlatılıyor...\n");
    
    // Komutu şifrele
    char cmd_json[2048];
    snprintf(cmd_json, sizeof(cmd_json), "{\"jwt\":\"%s\"}", jwt_token);
    char *protocol_message = create_encrypted_protocol_message("REPLY_QUERY", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreli sorgu mesajı oluşturulamadı!\n");
        return;
    }
    
    PRINTF_LOG("[CLIENT][REPLY_QUERY] Şifreli mesaj oluşturuldu, gönderiliyor...\n");
    
    // Mesajı socket'a direkt gönder (yanıt almayı kendimiz yapacağız)
    ssize_t bytes_sent = send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);
    if (bytes_sent < 0) {
        PRINTF_CLIENT("Şifreli sorgu gönderilemedi!\n");
        return;
    }
    PRINTF_LOG("[CLIENT][REPLY_QUERY] Mesaj gönderildi (%zd bytes), yanıt bekleniyor...\n", bytes_sent);
    
    PRINTF_LOG("[CLIENT][REPLY_QUERY] Mesaj gönderildi, yanıt bekleniyor...\n");
    
    // --- Parçalı yanıt toplama (REPLY_QUERY için) ---
    char* all_hex_data = NULL;
    size_t all_hex_len = 0;
    char* all_plain_data = NULL;
    size_t all_plain_len = 0;
    int expected_parts = 0, received_parts = 0;
    int done = 0;
    int recv_count = 0;
    char streambuf[65536];
    size_t streambuf_len = 0;
    
    while (!done) {
        // Eğer streambuf'da yeterli veri yoksa, recv ile tamamla
        if (streambuf_len < 4096) {
            ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
            recv_count++;
            PRINTF_LOG("[CLIENT][RECV] recv_count=%d, bytes_received=%zd, buffer_len=%zu\n", recv_count, pn, streambuf_len);
            if (pn <= 0) {
                PRINTF_LOG("[CLIENT][RECV] recv hatası veya bağlantı kapatıldı: %zd\n", pn);
                break;
            }
            streambuf_len += pn;
            streambuf[streambuf_len] = '\0';
            PRINTF_LOG("[CLIENT][RECV] Toplam buffer: %zu bytes, ilk 100 karakter: %.100s\n", streambuf_len, streambuf);
        }
        
        // ENCRYPTED:REPLY_QUERY: formatı kontrol et (tek parça encrypted)
        const char* single_encrypted_prefix = "ENCRYPTED:REPLY_QUERY:";
        if (strncmp(streambuf, single_encrypted_prefix, strlen(single_encrypted_prefix)) == 0) {
            const char* hex_data = streambuf + strlen(single_encrypted_prefix);
            char* newline = strchr(hex_data, '\n');
            size_t hex_len;
            
            if (newline) {
                hex_len = newline - hex_data;
            } else {
                // Newline yoksa, tüm kalan veriyi al
                hex_len = strlen(hex_data);
                // Eğer hex_len 0'dan büyükse ve son karakter \n ise, onu çıkar
                if (hex_len > 0 && hex_data[hex_len-1] == '\n') {
                    hex_len--;
                }
            }
            
            PRINTF_LOG("[CLIENT][SINGLE_ENC] Hex veri uzunluğu: %zu, newline var mı: %s\n", 
                       hex_len, newline ? "evet" : "hayır");
            
            if (hex_len > 0) {
                all_hex_data = malloc(hex_len + 1);
                memcpy(all_hex_data, hex_data, hex_len);
                all_hex_data[hex_len] = '\0';
                all_hex_len = hex_len;
                PRINTF_LOG("[CLIENT][SINGLE_ENC] Tek parça ENCRYPTED:REPLY_QUERY yanıtı alındı, hex_len=%zu\n", hex_len);
                PRINTF_LOG("[CLIENT][SINGLE_ENC] Hex data ilk 64 karakter: %.64s\n", all_hex_data);
                done = 1;
                break;
            }
        }
        
        // REPLY_QUERY: formatı kontrol et (tek parça plain)
        const char* single_plain_prefix = "REPLY_QUERY:";
        if (strncmp(streambuf, single_plain_prefix, strlen(single_plain_prefix)) == 0) {
            const char* plain_data = streambuf + strlen(single_plain_prefix);
            const char* newline = strchr(plain_data, '\n');
            if (!newline) newline = plain_data + strlen(plain_data); // Eğer \n yoksa sonuna kadar
            size_t plain_len = newline - plain_data;
            all_plain_data = malloc(plain_len + 1);
            memcpy(all_plain_data, plain_data, plain_len);
            all_plain_data[plain_len] = '\0';
            all_plain_len = plain_len;
            PRINTF_LOG("[CLIENT][SINGLE_PLAIN] Tek parça REPLY_QUERY yanıtı alındı, plain_len=%zu\n", plain_len);
            done = 1;
            break;
        }
        
        // ENCRYPTED_PART header'ı ara (çok parçalı encrypted)
        char* encrypted_header = strstr(streambuf, "ENCRYPTED_PART:");
        if (encrypted_header) {
            char* after_header = encrypted_header + 15;
            int idx = 0, total = 0;
            size_t plen = 0;
            int n = sscanf(after_header, "%d:%d:%zu:", &idx, &total, &plen);
            if (n != 3) {
                PRINTF_LOG("[CLIENT][PARSE] ENCRYPTED_PART header parse hatası!\n");
                break;
            }
            
            // Header'ın sonunu bul
            char* hex_start = after_header;
            int colon_count = 0;
            while (*hex_start && colon_count < 3) {
                if (*hex_start == ':') colon_count++;
                hex_start++;
            }
            
            // Yeterli hex verisi var mı kontrol et
            size_t available = streambuf + streambuf_len - hex_start;
            while (available < plen && recv_count < 10) {
                ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
                recv_count++;
                PRINTF_LOG("[CLIENT][RECV] hex_data tamamlanıyor, recv_count=%d, bytes=%zd\n", recv_count, pn);
                if (pn <= 0) break;
                streambuf_len += pn;
                streambuf[streambuf_len] = '\0';
                available = streambuf + streambuf_len - hex_start;
            }
            
            PRINTF_LOG("[CLIENT][ENC_PART] ENCRYPTED_PART idx=%d/%d, plen=%zu, available=%zu\n", idx, total, plen, available);
            
            all_hex_data = realloc(all_hex_data, all_hex_len + plen + 1);
            memcpy(all_hex_data + all_hex_len, hex_start, plen);
            all_hex_len += plen;
            all_hex_data[all_hex_len] = '\0';
            received_parts++;
            if (expected_parts == 0) expected_parts = total;
            
            // Tüketilen veriyi buffer'dan çıkar
            size_t consumed = (hex_start - streambuf) + plen;
            memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
            streambuf_len -= consumed;
            streambuf[streambuf_len] = '\0';
            
            if (received_parts >= expected_parts) { 
                PRINTF_LOG("[CLIENT][ENC_PART] Tüm ENCRYPTED parçalar alındı: %d/%d\n", received_parts, expected_parts);
                done = 1; 
                break; 
            }
            continue;
        }
        
        // PLAIN_PART header'ı ara (çok parçalı plain)
        char* plain_header = strstr(streambuf, "PLAIN_PART:REPLY_QUERY:");
        if (plain_header) {
            char* after_header = plain_header + 23; // "PLAIN_PART:REPLY_QUERY:" uzunluğu
            int idx = 0, total = 0;
            size_t plen = 0;
            int n = sscanf(after_header, "%d:%d:%zu:", &idx, &total, &plen);
            if (n != 3) {
                PRINTF_LOG("[CLIENT][PARSE] PLAIN_PART header parse hatası!\n");
                break;
            }
            
            // Header'ın sonunu bul
            char* data_start = after_header;
            int colon_count = 0;
            while (*data_start && colon_count < 3) {
                if (*data_start == ':') colon_count++;
                data_start++;
            }
            
            // Yeterli plain verisi var mı kontrol et
            size_t available = streambuf + streambuf_len - data_start;
            while (available < plen && recv_count < 10) {
                ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
                recv_count++;
                PRINTF_LOG("[CLIENT][RECV] plain_data tamamlanıyor, recv_count=%d, bytes=%zd\n", recv_count, pn);
                if (pn <= 0) break;
                streambuf_len += pn;
                streambuf[streambuf_len] = '\0';
                available = streambuf + streambuf_len - data_start;
            }
            
            PRINTF_LOG("[CLIENT][PLAIN_PART] PLAIN_PART idx=%d/%d, plen=%zu, available=%zu\n", idx, total, plen, available);
            
            all_plain_data = realloc(all_plain_data, all_plain_len + plen + 1);
            memcpy(all_plain_data + all_plain_len, data_start, plen);
            all_plain_len += plen;
            all_plain_data[all_plain_len] = '\0';
            received_parts++;
            if (expected_parts == 0) expected_parts = total;
            
            // Tüketilen veriyi buffer'dan çıkar
            size_t consumed = (data_start - streambuf) + plen;
            memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
            streambuf_len -= consumed;
            streambuf[streambuf_len] = '\0';
            
            if (received_parts >= expected_parts) { 
                PRINTF_LOG("[CLIENT][PLAIN_PART] Tüm PLAIN parçalar alındı: %d/%d\n", received_parts, expected_parts);
                done = 1; 
                break; 
            }
            continue;
        }
        
        // Hiçbir format bulunamadı, çok fazla deneme yapıldı
        if (recv_count > 5) {
            PRINTF_LOG("[CLIENT][TIMEOUT] Çok fazla recv denemesi yapıldı, çıkılıyor...\n");
            break;
        }
    }
    
    PRINTF_LOG("[CLIENT][RESULT] recv_count=%d, all_hex_len=%zu, all_plain_len=%zu\n", 
               recv_count, all_hex_len, all_plain_len);
    
    // Sonuçları işle
    if (all_hex_data && all_hex_len > 16) {
        PRINTF_LOG("[CLIENT][DECRYPT] Encrypted data çözülüyor...\n");
        char* decrypted = decrypt_protocol_message(all_hex_data, conn->ecdh_ctx.aes_key);
        if (decrypted) {
            PRINTF_CLIENT("\n[REPLY_QUERY] Şifreli cevap çözüldü:\n%s\n", decrypted);
            free(decrypted);
        } else {
            PRINTF_CLIENT("Şifreli cevap çözülemedi!\n");
        }
        free(all_hex_data);
    } else if (all_plain_data && all_plain_len > 0) {
        PRINTF_CLIENT("\n[REPLY_QUERY] Plain cevap alındı:\n%s\n", all_plain_data);
        free(all_plain_data);
    } else {
        PRINTF_CLIENT("Reply sorgusu başarısız veya bağlantı hatası!\n");
        if (all_hex_data) free(all_hex_data);
        if (all_plain_data) free(all_plain_data);
    }
}

void query_my_replies(client_connection_t* conn, const char* jwt_token) {
    if (!conn || !jwt_token || strlen(jwt_token) == 0) {
        PRINTF_CLIENT("JWT token veya bağlantı hatalı!\n");
        return;
    }
    if (!conn->ecdh_initialized) {
        PRINTF_CLIENT("ECDH başlatılmamış - şifreli sorgu yapılamaz!\n");
        return;
    }
    
    PRINTF_LOG("[CLIENT][QUERY_MY_REPLIES] Raporlarıma gelen cevapları sorgulama başlatılıyor...\n");
    
    // JSON komutu oluştur
    char cmd_json[2048];
    snprintf(cmd_json, sizeof(cmd_json), "{\"jwt\":\"%s\"}", jwt_token);
    
    // QUERY_MY_REPLIES komutu şifrele ve gönder
    char* protocol_message = create_encrypted_protocol_message("QUERY_MY_REPLIES", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }
    
    // Mesajı socket'a direkt gönder
    ssize_t bytes_sent = send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);
    if (bytes_sent < 0) {
        PRINTF_CLIENT("Şifreli sorgu gönderilemedi!\n");
        return;
    }
    
    PRINTF_LOG("QUERY_MY_REPLIES komutu gönderildi (%zd bytes), yanıt bekleniyor...\n", bytes_sent);
    
    // --- Parçalı yanıt toplama (QUERY_MY_REPLIES için) ---
    char* all_hex_data = NULL;
    size_t all_hex_len = 0;
    int recv_count = 0;
    int done = 0;
    char streambuf[65536];
    size_t streambuf_len = 0;
    
    while (!done) {
        // Eğer streambuf'da yeterli veri yoksa, recv ile tamamla
        if (streambuf_len < 4096) {
            ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
            recv_count++;
            PRINTF_LOG("[CLIENT][RECV] recv_count=%d, bytes_received=%zd, buffer_len=%zu\n", recv_count, pn, streambuf_len);
            if (pn <= 0) {
                PRINTF_LOG("[CLIENT][RECV] recv hatası veya bağlantı kapatıldı: %zd\n", pn);
                break;
            }
            streambuf_len += pn;
            streambuf[streambuf_len] = '\0';
            PRINTF_LOG("[CLIENT][RECV] Toplam buffer: %zu bytes\n", streambuf_len);
        }
        
        // ENCRYPTED:QUERY_MY_REPLIES: formatı kontrol et (tek parça encrypted)
        const char* single_encrypted_prefix = "ENCRYPTED:QUERY_MY_REPLIES:";
        if (strncmp(streambuf, single_encrypted_prefix, strlen(single_encrypted_prefix)) == 0) {
            const char* hex_data = streambuf + strlen(single_encrypted_prefix);
            char* newline = strchr(hex_data, '\n');
            size_t hex_len;
            
            if (newline) {
                hex_len = newline - hex_data;
            } else {
                hex_len = strlen(hex_data);
                if (hex_len > 0 && hex_data[hex_len-1] == '\n') {
                    hex_len--;
                }
            }
            
            PRINTF_LOG("[CLIENT][SINGLE_ENC] Hex veri uzunluğu: %zu\n", hex_len);
            
            if (hex_len > 0) {
                all_hex_data = malloc(hex_len + 1);
                memcpy(all_hex_data, hex_data, hex_len);
                all_hex_data[hex_len] = '\0';
                all_hex_len = hex_len;
                PRINTF_LOG("[CLIENT][SINGLE_ENC] Tek parça ENCRYPTED:QUERY_MY_REPLIES yanıtı alındı, hex_len=%zu\n", hex_len);
                done = 1;
            }
        } else {
            // Başka format veya veri bekleniyor
            PRINTF_LOG("[CLIENT] Beklenen format bulunamadı, daha fazla veri bekleniyor...\n");
            continue;
        }
    }
    
    // Decrypt işlemi
    if (all_hex_data && all_hex_len > 0) {
        PRINTF_LOG("[CLIENT][DECRYPT] Hex veri decrypt ediliyor...\n");
        
        size_t encrypted_length;
        uint8_t* encrypted_bytes = hex_to_bytes(all_hex_data, &encrypted_length);
        if (!encrypted_bytes || encrypted_length < CRYPTO_IV_SIZE) {
            PRINTF_LOG("[CLIENT][DECRYPT] Hex decode hatası!\n");
            if (encrypted_bytes) free(encrypted_bytes);
            free(all_hex_data);
            return;
        }
        
        uint8_t iv[CRYPTO_IV_SIZE];
        memcpy(iv, encrypted_bytes, CRYPTO_IV_SIZE);
        
        char* decrypted_json = decrypt_data(
            encrypted_bytes + CRYPTO_IV_SIZE,
            encrypted_length - CRYPTO_IV_SIZE,
            conn->ecdh_ctx.aes_key,
            iv
        );
        
        free(encrypted_bytes);
        free(all_hex_data);
        
        if (decrypted_json) {
            PRINTF_LOG("[CLIENT][DECRYPT] Decrypt başarılı!\n");
            PRINTF_LOG("\n=== RAPORLARIMA GELEN CEVAPLAR ===\n");
            PRINTF_LOG("%s\n", decrypted_json);
            PRINTF_LOG("=====================================\n");
            free(decrypted_json);
        } else {
            PRINTF_LOG("[CLIENT][DECRYPT] Decrypt hatası!\n");
        }
    } else {
        PRINTF_LOG("[CLIENT] Hex veri alınamadı!\n");
    }
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

int admin_reply_to_report(client_connection_t* conn, const char* jwt_token) {
    int report_id;
    char msg[900];
    printf("Rapor ID girin: ");
    if (scanf("%d", &report_id) != 1) {
        printf("Geçersiz rapor ID!\n");
        while (getchar() != '\n');
        return -1;
    }
    while (getchar() != '\n'); // Temizle
    printf("Mesajınızı girin: ");
    if (fgets(msg, sizeof(msg), stdin) == NULL) {
        printf("Mesaj okunamadı!\n");
        return -1;
    }
    msg[strcspn(msg, "\n")] = 0;
    if (strlen(msg) == 0) {
        printf("Mesaj boş olamaz!\n");
        return -1;
    }
    PRINTF_LOG("Sifreleme islemi baslatiliyor...\n");
    if (!conn->ecdh_initialized) {
        PRINTF_LOG("ECDH başlatılmamış - şifreleme yapılamaz\n");
        return -1;
    }
    char json_content[1024];
    snprintf(json_content, sizeof(json_content), "{\"report_id\":%d,\"msg\":\"%s\"}", report_id, msg);
    char *protocol_message = create_encrypted_protocol_message("REPLY_REPORT", json_content, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        printf("Şifreli mesaj oluşturulamadı!\n");
        return -1;
    }
    int result = try_send_message_current_connection(conn, protocol_message);
    if (result < 0) {
        PRINTF_LOG("Mevcut bağlantı ile gönderim başarısız, UDP fallback deneniyor...\n");
        result = admin_reply_to_report_udp_fallback(conn, report_id, msg, jwt_token);
    }
    if (result < 0) {
        PRINTF_LOG("UDP fallback başarısız, P2P fallback deneniyor...\n");
        result = admin_reply_to_report_p2p_fallback(conn, report_id, msg, jwt_token);
    }
    free(protocol_message);
    if (result < 0) {
        printf("Tüm bağlantı tipleriyle gönderim başarısız!\n");
        return -1;
    }
    printf("Rapor cevabı şifreli olarak gönderildi ve işlem tamamlandı.\n");
    return 0;
}