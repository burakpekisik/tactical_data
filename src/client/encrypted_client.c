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
#include "crypto_utils.h"
#include "config.h"
#include "encrypted_client.h"
#include "fallback_manager.h"
#include "protocol_manager.h"
#include "logger.h"
#include "../user/login_user.h" // login_user_with_argon2 prototipi burada olmalı
#include <pthread.h>
 
char jwt_token[1024] = ""; // Global JWT token

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
    pthread_t reply_thread;
    pthread_create(&reply_thread, NULL, report_reply_listener_thread, conn);
    pthread_detach(reply_thread);
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
                if (!conn->ecdh_initialized) {
                    PRINTF_LOG("ECDH başlatılmamış - şifreli rapor listesi alınamaz\n");
                    break;
                }
                {
                    char report_query[2048];
                    snprintf(report_query, sizeof(report_query), "{\"command\":\"REPORT_QUERY\",\"jwt\":\"%s\"}", jwt_token);
                    char *encrypted_message = create_encrypted_protocol_message("REPORT_QUERY", report_query, conn->ecdh_ctx.aes_key, jwt_token);
                    if (!encrypted_message) {
                        PRINTF_LOG("Şifreli rapor sorgu mesajı oluşturulamadı\n");
                        break;
                    }
                    send(conn->socket, encrypted_message, strlen(encrypted_message), 0);
                    free(encrypted_message);
                    char recvbuf[32768];
                    ssize_t n = recv(conn->socket, recvbuf, sizeof(recvbuf)-1, 0);
                    if (n > 0) {
                        recvbuf[n] = '\0';
                        // Şifreli yanıtı çöz
                        if (strncmp(recvbuf, "ENCRYPTED:REPORT_QUERY:", 22) == 0) {
                            const char* hex_data = recvbuf + 22;
                            // Eğer ilk karakter ':' ise atla
                            if (*hex_data == ':') hex_data++;
                            while (*hex_data == ' ' || *hex_data == '\n' || *hex_data == '\r' || *hex_data == '\t') hex_data++;
                            size_t hex_len = strlen(hex_data);
                            while (hex_len > 0 && (hex_data[hex_len-1] == '\n' || hex_data[hex_len-1] == '\r' || hex_data[hex_len-1] == ' ' || hex_data[hex_len-1] == '\t')) {
                                ((char*)hex_data)[hex_len-1] = '\0';
                                hex_len--;
                            }
                            PRINTF_LOG("[DEBUG] Gelen hex_data uzunluğu: %zu\n", hex_len);
                            PRINTF_LOG("[DEBUG] İlk 32 karakter: %.32s\n", hex_data);
                            size_t encrypted_length;
                            uint8_t* encrypted_bytes = hex_to_bytes(hex_data, &encrypted_length);
                            if (encrypted_bytes && encrypted_length > 16) {
                                uint8_t iv[16];
                                memcpy(iv, encrypted_bytes, 16);
                                char* decrypted_json = decrypt_data(
                                    encrypted_bytes + 16,
                                    encrypted_length - 16,
                                    conn->ecdh_ctx.aes_key,
                                    iv
                                );
                                if (decrypted_json) {
                                    PRINTF_CLIENT("\nRapor Listesi (Çözüldü):\n%s\n", decrypted_json);
                                    free(decrypted_json);
                                } else {
                                    PRINTF_CLIENT("Rapor listesi şifresi çözülemedi!\n");
                                }
                                free(encrypted_bytes);
                            } else {
                                PRINTF_CLIENT("Rapor listesi yanıtı hatalı! (hex_data uzunluğu: %zu)\n", hex_len);
                            }
                        } else {
                            PRINTF_CLIENT("Rapor listesi alınamadı veya bağlantı hatası!\n");
                        }
                    } else {
                        PRINTF_CLIENT("Rapor listesi alınamadı veya bağlantı hatası!\n");
                    }
                }
                break;
                
            case 4: // Cikis
            {
                LOG_CLIENT_INFO("User requested shutdown");
                PRINTF_CLIENT("Baglanti kapatiliyor...\n");
                close_connection(conn);
                LOG_CLIENT_INFO("Connection closed, shutting down client");
                logger_cleanup(LOGGER_CLIENT);
                return 0;
            }
            case 5: // Admin bildirimlerini dinle
                listen_for_admin_notifications(conn);
                break;
            case 6: // Admin rapora cevap ver
            {
                int report_id;
                char msg[900];
                printf("Rapor ID girin: ");
                if (scanf("%d", &report_id) != 1) {
                    printf("Geçersiz rapor ID!\n");
                    while (getchar() != '\n');
                    break;
                }
                while (getchar() != '\n'); // Temizle
                printf("Mesajınızı girin: ");
                if (fgets(msg, sizeof(msg), stdin)) {
                    msg[strcspn(msg, "\n")] = 0;
                    if (strlen(msg) > 0) {
                        char cmd[1200];
                        snprintf(cmd, sizeof(cmd), "REPLY_REPORT:%d:%s", report_id, msg);
                        send(conn->socket, cmd, strlen(cmd), 0);
                        printf("Rapor cevabı gönderildi.\n");
                    } else {
                        printf("Mesaj boş olamaz!\n");
                    }
                }
                break;
            }
            case 7: // Gelen admin cevaplarını görüntüle
                watch_report_replies();
                break;
            default:
                PRINTF_LOG("Gecersiz secim. Lutfen 1-7 arasi bir sayi girin.\n");
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
    PRINTF_LOG("4. Cikis\n");
    PRINTF_LOG("5. Admin bildirimlerini dinle (admin için)\n");
    PRINTF_LOG("6. Raporlara cevap ver (admin)\n");
    PRINTF_LOG("7. Gelen admin cevaplarını görüntüle\n");
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
    
    // İlk olarak mevcut bağlantı türüyle dene
    int result = try_send_message_current_connection(conn, protocol_message);
    
    if (result < 0) {
        PRINTF_LOG("Mevcut bağlantı türü (%s) ile gönderim başarısız, fallback deneniyor...\n", 
               get_connection_type_name(conn->type));
        
        // Fallback metodlarını dene (jwt_token parametresi eklendi)
        result = try_send_message_with_fallback(conn, protocol_message, filename, content, encrypt, jwt_token);
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
    if (conn->type == CONN_TCP) {
        bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    } else if (conn->type == CONN_UDP) {
        bytes_received = receive_udp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    } else if (conn->type == CONN_P2P) {
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
        conn->type = CONN_TCP;
        
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
        conn->type = CONN_UDP;
        
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
        conn->type = CONN_P2P;
        
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

// Gelen admin cevaplarını saklamak için yapı
#define MAX_REPORT_REPLIES 100
struct report_reply_entry {
    int report_id;
    char msg[900];
};
static struct report_reply_entry report_replies[MAX_REPORT_REPLIES];
static int report_reply_count = 0;
static pthread_mutex_t report_reply_mutex = PTHREAD_MUTEX_INITIALIZER;

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

void watch_report_replies(void) {
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

// ECDH sonrası sunucuya HELLO mesajı gönder
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