/**
 * @file fallback_manager.c
 * @brief Bağlantı yedekleme ve fallback mekanizması implementasyonu
 * @details Bu dosya, ağ bağlantılarında sorun yaşandığında alternatif protokollere
 *          otomatik geçiş yapan fallback sisteminin implementasyonunu içerir.
 *          TCP/UDP/P2P protokolleri arasında dinamik geçiş ve ECDH yeniden kurulumu sağlar.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 * @ingroup fallback
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

/**
 * @brief Bağlantı türünün string karşılığını döner
 * @details Connection type enum'ından insan okunabilir string formatına dönüştürür.
 *          Debug ve log mesajlarında kullanılır.
 * @param type Dönüştürülecek bağlantı türü
 * @return const char* Bağlantı türünün metinsel karşılığı
 * @note Bu fonksiyon sadece okunabilir string döner, bellek tahsisi yapmaz
 */
const char* get_connection_type_name(connection_type_t type) {
    switch (type) {
        case CONN_TCP: return "TCP";
        case CONN_UDP: return "UDP";
        case CONN_P2P: return "P2P";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Mevcut bağlantı türüyle mesaj göndermeyi dener
 * @details Verilen bağlantının türüne göre uygun protokol-spesifik gönderim
 *          fonksiyonunu çağırır. Bu, fallback mekanizmasının ilk adımıdır.
 * @param conn Aktif client bağlantısı (tür bilgisi içerir)
 * @param message Gönderilecek protokol mesajı
 * @return int Gönderim sonucu (>= 0: başarılı, < 0: hata)
 * @note Bu fonksiyon protocol_manager.h'daki send_*_message fonksiyonlarını kullanır
 * @see send_tcp_message(), send_udp_message(), send_p2p_message()
 */
int try_send_message_current_connection(client_connection_t* conn, const char* message) {
    int result = -1;
    
    if (conn->type == CONN_TCP) {
        result = send_tcp_message(conn, message);
    } else if (conn->type == CONN_UDP) {
        result = send_udp_message(conn, message);
    } else if (conn->type == CONN_P2P) {
        result = send_p2p_message(conn, message);
    } else {
        PRINTF_LOG("Bilinmeyen baglanti tipi\n");
    }
    
    return result;
}

/**
 * @brief Fallback mekanizması ile mesaj göndermeyi dener
 * @details Ana bağlantı başarısız olduğunda alternatif protokolleri sırasıyla dener.
 *          Her fallback için yeni bağlantı kurar, ECDH yeniden yapar ve mesajı uyarlar.
 *          Başarılı fallback sonrası ana bağlantı yapısını günceller.
 * 
 * Fallback Sırası:
 * - Mevcut protokol dışındaki diğer protokoller
 * - Her protokol için tam bağlantı kurulumu
 * - Şifreli mesajlar için yeni anahtar ile yeniden şifreleme
 * 
 * @param conn Ana bağlantı yapısı (başarılı fallback sonrası güncellenir)
 * @param protocol_message Orijinal protokol mesajı
 * @param filename Dosya adı (yeniden şifreleme için)
 * @param content Ham dosya içeriği (yeniden şifreleme için)
 * @param encrypt Şifreleme durumu (1: şifreli, 0: normal)
 * @return int İşlem sonucu (>= 0: başarılı, < 0: tüm fallback başarısız)
 * 
 * @note Başarılı fallback sonrası:
 *       - Ana bağlantının socket'i, türü ve portu güncellenir
 *       - ECDH context yeni bağlantıdan kopyalanır
 *       - Eski socket kapatılır
 * 
 * @warning Şifreli mesajlar her fallback için yeni ECDH anahtarı ile yeniden şifrelenir
 */
int try_send_message_with_fallback(client_connection_t* conn, const char* protocol_message, 
                                   const char* filename, const char* content, int encrypt) {
    // Fallback sırası: mevcut tip haricinde diğerlerini dene
    connection_type_t fallback_order[3];
    int fallback_count = 0;
    
    // Mevcut tip dışındaki tipleri sıraya koy
    if (conn->type != CONN_TCP) {
        fallback_order[fallback_count++] = CONN_TCP;
    }
    if (conn->type != CONN_UDP) {
        fallback_order[fallback_count++] = CONN_UDP;
    }
    if (conn->type != CONN_P2P) {
        fallback_order[fallback_count++] = CONN_P2P;
    }
    
    // Her fallback tipini dene
    for (int i = 0; i < fallback_count; i++) {
        connection_type_t fallback_type = fallback_order[i];
        PRINTF_LOG("Fallback deneniyor: %s\n", get_connection_type_name(fallback_type));
        
        // Yeni bağlantı tipi için socket oluştur ve bağlan
        client_connection_t* fallback_conn = create_fallback_connection(conn, fallback_type);
        if (fallback_conn == NULL) {
            PRINTF_LOG("Fallback bağlantı oluşturulamadı: %s\n", get_connection_type_name(fallback_type));
            continue;
        }
        
        // Fallback bağlantısı için protokol mesajını yeniden oluştur
        char* fallback_message = NULL;
        
        // Şifreli mesaj mı kontrol et
        if (encrypt && strncmp(protocol_message, "ENCRYPTED:", 10) == 0) {
            // Şifreli mesaj için yeni ECDH anahtarıyla yeniden şifrele
            PRINTF_LOG("Fallback için JSON yeniden şifreleniyor...\n");
            
            if (!fallback_conn->ecdh_initialized) {
                PRINTF_LOG("Fallback ECDH başlatılmamış - şifreleme yapılamaz\n");
                close_connection(fallback_conn);
                continue;
            }
            
            // Yeni anahtar ile yeniden şifrele
            fallback_message = create_encrypted_protocol_message(filename, content, fallback_conn->ecdh_ctx.aes_key);
            if (fallback_message == NULL) {
                PRINTF_LOG("Fallback şifreleme başarısız\n");
                close_connection(fallback_conn);
                continue;
            }
        } else {
            // Normal mesaj - protokol tipine göre uyarla
            fallback_message = adapt_message_for_protocol(protocol_message, fallback_type);
            if (fallback_message == NULL) {
                fallback_message = (char*)protocol_message; // Varsayılan olarak orijinal mesajı kullan
            }
        }
        
        // Mesajı göndermeyi dene
        int result = try_send_message_current_connection(fallback_conn, fallback_message);
        
        if (result >= 0) {
            PRINTF_LOG("✓ Fallback başarılı: %s\n", get_connection_type_name(fallback_type));
            
            // Ana bağlantıyı güncelle
            close(conn->socket);
            conn->socket = fallback_conn->socket;
            conn->type = fallback_conn->type;
            conn->port = fallback_conn->port;
            conn->server_addr = fallback_conn->server_addr;
            
            // ECDH context'i güncelle (eğer yeni bağlantıda varsa)
            if (fallback_conn->ecdh_initialized) {
                if (conn->ecdh_initialized) {
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                }
                conn->ecdh_ctx = fallback_conn->ecdh_ctx;
                conn->ecdh_initialized = true;
            }
            
            // Fallback connection wrapper'ı temizle (socket'i almadığımız için)
            free(fallback_conn);
            
            // Mesajı temizle (eğer yeniden oluşturulmuşsa)
            if (fallback_message != protocol_message && fallback_message != NULL) {
                free(fallback_message);
            }
            
            return result;
        }
        
        PRINTF_LOG("✗ Fallback başarısız: %s\n", get_connection_type_name(fallback_type));
        
        // Fallback bağlantısını temizle
        close_connection(fallback_conn);
        
        // Mesajı temizle (eğer yeniden oluşturulmuşsa)
        if (fallback_message != protocol_message && fallback_message != NULL) {
            free(fallback_message);
        }
    }
    
    return -1; // Tüm fallback'ler başarısız
}

/**
 * @brief Belirli protokol türü için yeni fallback bağlantısı oluşturur
 * @details Orijinal bağlantının IP adresini kullanarak hedef protokol türünde
 *          yeni bir bağlantı kurar. Her protokol için uygun port ve socket türü seçer.
 *          Bağlantı kurulduktan sonra ECDH anahtar değişimi yapar.
 * 
 * Protokol-Port Eşleştirmesi:
 * - TCP: CONFIG_PORT (8080) - SOCK_STREAM
 * - UDP: CONFIG_UDP_PORT (8081) - SOCK_DGRAM  
 * - P2P: CONFIG_P2P_PORT (8082) - SOCK_STREAM
 * 
 * @param original_conn Orijinal bağlantı (IP adresi alınır)
 * @param target_type Hedef protokol türü
 * @return client_connection_t* Yeni fallback bağlantısı (NULL: başarısız)
 * 
 * @note Bağlantı Kurulum Süreci:
 *       1. Bellek tahsisi ve struct başlatma
 *       2. Socket oluşturma (protokole uygun tür)
 *       3. Bağlantı kurma (TCP/P2P) veya test ping (UDP)
 *       4. ECDH anahtar değişimi
 * 
 * @warning Dönen bağlantı close_connection() ile kapatılmalıdır
 */
client_connection_t* create_fallback_connection(client_connection_t* original_conn, connection_type_t target_type) {
    client_connection_t* fallback_conn = malloc(sizeof(client_connection_t));
    if (fallback_conn == NULL) {
        PRINTF_LOG("Fallback connection için bellek tahsis hatası\n");
        return NULL;
    }
    
    // Connection struct'i başlat
    memset(fallback_conn, 0, sizeof(client_connection_t));
    fallback_conn->type = target_type;
    
    // Server address'i kopyala
    fallback_conn->server_addr = original_conn->server_addr;
    
    // Target type'a göre port ve socket ayarla
    int port;
    int sock_type;
    
    switch (target_type) {
        case CONN_TCP:
            port = CONFIG_PORT;
            sock_type = SOCK_STREAM;
            break;
        case CONN_UDP:
            port = CONFIG_UDP_PORT;
            sock_type = SOCK_DGRAM;
            break;
        case CONN_P2P:
            port = CONFIG_P2P_PORT;
            sock_type = SOCK_STREAM;
            break;
        default:
            PRINTF_LOG("Geçersiz fallback connection tipi\n");
            free(fallback_conn);
            return NULL;
    }
    
    fallback_conn->port = port;
    fallback_conn->server_addr.sin_port = htons(port);
    
    // Socket oluştur
    fallback_conn->socket = socket(AF_INET, sock_type, 0);
    if (fallback_conn->socket < 0) {
        PRINTF_LOG("Fallback socket oluşturulamadı\n");
        free(fallback_conn);
        return NULL;
    }
    
    // Bağlantı kur
    if (target_type == CONN_TCP || target_type == CONN_P2P) {
        // TCP/P2P için connect
        if (connect(fallback_conn->socket, (struct sockaddr*)&fallback_conn->server_addr, 
                   sizeof(fallback_conn->server_addr)) < 0) {
            PRINTF_LOG("Fallback %s bağlantısı kurulamadı\n", get_connection_type_name(target_type));
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
        
        // ECDH key exchange (TCP ve P2P için)
        if (!setup_ecdh_for_fallback(fallback_conn)) {
            PRINTF_LOG("Fallback ECDH kurulumu başarısız\n");
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
        
    } else if (target_type == CONN_UDP) {
        // UDP için test ping
        const char* test_msg = "PING";
        if (sendto(fallback_conn->socket, test_msg, strlen(test_msg), 0,
                   (struct sockaddr*)&fallback_conn->server_addr, sizeof(fallback_conn->server_addr)) <= 0) {
            PRINTF_LOG("Fallback UDP test ping gönderilemedi\n");
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
        
        // UDP response bekle
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(fallback_conn->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        char test_buffer[64];
        if (recvfrom(fallback_conn->socket, test_buffer, sizeof(test_buffer) - 1, 0, NULL, 0) <= 0) {
            PRINTF_LOG("Fallback UDP test response alınamadı\n");
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
        
        // UDP ECDH setup
        if (!setup_udp_ecdh_for_fallback(fallback_conn)) {
            PRINTF_LOG("Fallback UDP ECDH kurulumu başarısız\n");
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
    }
    
    PRINTF_LOG("✓ Fallback bağlantı kuruldu: %s (Port: %d)\n", 
           get_connection_type_name(target_type), port);
    
    return fallback_conn;
}

/**
 * @brief TCP/P2P bağlantıları için ECDH anahtar değişimi kurulumu
 * @details Stream tabanlı protokoller (TCP/P2P) için standart ECDH prosedürü.
 *          Binary formatta anahtar değişimi yapar ve AES256 oturum anahtarı üretir.
 * 
 * ECDH Kurulum Süreci:
 * 1. ECDH context başlatma
 * 2. Anahtar çifti üretme
 * 3. Server'ın public key'ini alma (binary)
 * 4. Kendi public key'ini gönderme (binary)
 * 5. Shared secret hesaplama
 * 6. AES256 anahtarı türetme
 * 
 * @param conn Kurulacak fallback bağlantısı
 * @return bool İşlem sonucu
 * @retval true ECDH başarıyla kuruldu, conn->ecdh_initialized = true
 * @retval false ECDH kurulumu başarısız, context temizlendi
 * 
 * @note Bu fonksiyon sadece TCP ve P2P bağlantıları için kullanılır
 * @see setup_udp_ecdh_for_fallback() UDP için özel implementasyon
 */
bool setup_ecdh_for_fallback(client_connection_t* conn) {
    if (!ecdh_init_context(&conn->ecdh_ctx)) {
        PRINTF_LOG("Fallback ECDH context başlatılamadı\n");
        return false;
    }
    
    if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
        PRINTF_LOG("Fallback ECDH anahtar çifti üretilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Server'in public key'ini al
    uint8_t server_public_key[ECC_PUB_KEY_SIZE];
    ssize_t received = recv(conn->socket, server_public_key, ECC_PUB_KEY_SIZE, 0);
    if (received != ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("Fallback Server public key alınamadı\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Kendi public key'imizi gönder
    ssize_t sent = send(conn->socket, conn->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
    if (sent != ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("Fallback Public key gönderilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Shared secret hesapla
    if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
        PRINTF_LOG("Fallback Shared secret hesaplanamadı\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // AES anahtarını türet
    if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
        PRINTF_LOG("Fallback AES anahtarı türetilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    conn->ecdh_initialized = true;
    PRINTF_LOG("✓ Fallback ECDH anahtar değişimi tamamlandı\n");
    return true;
}

/**
 * @brief UDP bağlantısı için ECDH anahtar değişimi kurulumu
 * @details Datagram tabanlı protokol (UDP) için özel ECDH prosedürü.
 *          Hex-encoded string formatında anahtar değişimi yapar.
 * 
 * UDP ECDH Kurulum Süreci:
 * 1. ECDH context başlatma ve anahtar çifti üretme
 * 2. "ECDH_INIT" mesajı gönderme
 * 3. Server'dan "ECDH_PUB:xxxx" mesajı alma
 * 4. Hex string'i binary'ye çevirme
 * 5. "ECDH_PUB:xxxx" ile kendi key'ini gönderme
 * 6. Shared secret hesaplama ve AES anahtarı türetme
 * 7. "ECDH_OK" onay mesajını bekleme
 * 
 * @param conn Kurulacak UDP fallback bağlantısı
 * @return bool İşlem sonucu
 * @retval true UDP ECDH başarıyla kuruldu
 * @retval false UDP ECDH kurulumu başarısız
 * 
 * @note UDP için özel mesaj formatları kullanılır:
 *       - ECDH_INIT: Anahtar değişimi başlatma
 *       - ECDH_PUB:hex_data: Public key gönderimi
 *       - ECDH_OK: Başarılı tamamlanma onayı
 * 
 * @warning UDP'de packet loss olabileceği için timeout mekanizması var
 */
bool setup_udp_ecdh_for_fallback(client_connection_t* conn) {
    if (!ecdh_init_context(&conn->ecdh_ctx)) {
        PRINTF_LOG("Fallback UDP ECDH context başlatılamadı\n");
        return false;
    }
    
    if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
        PRINTF_LOG("Fallback UDP ECDH anahtar çifti üretilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // ECDH init mesajı gönder
    const char* ecdh_init = "ECDH_INIT";
    if (sendto(conn->socket, ecdh_init, strlen(ecdh_init), 0,
              (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) < 0) {
        PRINTF_LOG("Fallback UDP ECDH init mesajı gönderilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Server'in public key'ini bekle
    char server_response[1024];
    ssize_t received = recvfrom(conn->socket, server_response, sizeof(server_response) - 1, 0, NULL, 0);
    if (received < 0) {
        PRINTF_LOG("Fallback UDP Server public key alınamadı\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    server_response[received] = '\0';
    
    // "ECDH_PUB:" prefix'ini kontrol et
    if (strncmp(server_response, "ECDH_PUB:", 9) != 0) {
        PRINTF_LOG("Fallback UDP Geçersiz server response: %s\n", server_response);
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Server public key'ini decode et
    size_t server_key_len;
    uint8_t* server_public_key = hex_to_bytes(server_response + 9, &server_key_len);
    if (server_public_key == NULL || server_key_len != ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("Fallback UDP Server public key decode hatası\n");
        if (server_public_key) free(server_public_key);
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
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
        PRINTF_LOG("Fallback UDP Client public key gönderilemedi\n");
        free(server_public_key);
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Shared secret hesapla
    if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
        PRINTF_LOG("Fallback UDP Shared secret hesaplanamadı\n");
        free(server_public_key);
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // AES anahtarını türet
    if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
        PRINTF_LOG("Fallback UDP AES anahtarı türetilemedi\n");
        free(server_public_key);
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    free(server_public_key);
    
    // Onay mesajını bekle
    char ack_buffer[64];
    ssize_t ack_received = recvfrom(conn->socket, ack_buffer, sizeof(ack_buffer) - 1, 0, NULL, 0);
    if (ack_received > 0) {
        ack_buffer[ack_received] = '\0';
        if (strcmp(ack_buffer, "ECDH_OK") == 0) {
            conn->ecdh_initialized = true;
            PRINTF_LOG("✓ Fallback UDP ECDH anahtar değişimi tamamlandı\n");
            return true;
        }
    }
    
    PRINTF_LOG("Fallback UDP ECDH onay mesajı alınamadı\n");
    ecdh_cleanup_context(&conn->ecdh_ctx);
    return false;
}

/**
 * @brief Mesajı hedef protokol türüne göre uyarlar
 * @details Farklı protokoller için mesaj formatını optimize eder ve
 *          protokol-spesifik prefix'ler ekler. Özellikle P2P protokolü
 *          için özel format gereklidir.
 * 
 * Protokol Adaptasyonları:
 * - TCP: Orijinal mesaj (adaptasyon gerekmez)
 * - UDP: Orijinal mesaj (adaptasyon gerekmez)  
 * - P2P: Özel prefix eklenir
 *   - Şifreli veri: "P2P_ENCRYPTED:original_message"
 *   - Normal veri: "P2P_DATA:CLIENT_pid:original_message"
 * 
 * @param original_message Orijinal protokol mesajı
 * @param target_type Hedef protokol türü
 * @return char* Uyarlanmış mesaj (NULL: adaptasyon gerekmez)
 * 
 * @note NULL dönerse orijinal mesaj kullanılır
 * @warning Dönen pointer (NULL değilse) free() ile serbest bırakılmalıdır
 * 
 * @example
 * @code
 * // P2P için mesaj adaptasyonu
 * char* adapted = adapt_message_for_protocol("ENCRYPTED:data", CONN_P2P);
 * // Sonuç: "P2P_ENCRYPTED:ENCRYPTED:data"
 * @endcode
 */
char* adapt_message_for_protocol(const char* original_message, connection_type_t target_type) {
    // P2P için özel format gerekiyor
    if (target_type == CONN_P2P) {
        char* adapted_message = malloc(CONFIG_BUFFER_SIZE);
        if (adapted_message == NULL) {
            return NULL;
        }
        
        // Şifreli veri mi kontrol et (ENCRYPTED: ile başlıyor mu?)
        if (strncmp(original_message, "ENCRYPTED:", 10) == 0) {
            // Şifreli veri için P2P_ENCRYPTED formatında gönder
            snprintf(adapted_message, CONFIG_BUFFER_SIZE, "P2P_ENCRYPTED:%s", original_message);
        } else {
            // Normal veri için P2P_DATA formatında gönder
            snprintf(adapted_message, CONFIG_BUFFER_SIZE, "P2P_DATA:CLIENT_%d:%s", 
                     getpid(), original_message);
        }
        
        return adapted_message;
    }
    
    // TCP ve UDP için orijinal mesajı kullan
    return NULL; // NULL dönerse orijinal mesaj kullanılır
}
