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
    
    LOG_CLIENT_INFO("Successfully connected to server");
    PRINTF_CLIENT("Server'a basariyla baglandi\n");
    
    while (1) {
        show_menu();
        PRINTF_LOG("Seciminiz: ");
        
        if (scanf("%d", &choice) != 1) {
            PRINTF_LOG("Gecersiz secim\n");
            while (getchar() != '\n'); // Buffer temizle
            continue;
        }
        
        while (getchar() != '\n'); // Buffer temizle
        
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
                
            case 3: // Cikis
                LOG_CLIENT_INFO("User requested shutdown");
                PRINTF_CLIENT("Baglanti kapatiliyor...\n");
                close_connection(conn);
                LOG_CLIENT_INFO("Connection closed, shutting down client");
                logger_cleanup(LOGGER_CLIENT);
                return 0;
                
            default:
                PRINTF_LOG("Gecersiz secim. Lutfen 1-3 arasi bir sayi girin.\n");
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
    PRINTF_LOG("3. Cikis\n");
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