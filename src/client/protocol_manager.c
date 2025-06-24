/**
 * @file protocol_manager.c
 * @brief Protokol yönetimi ve mesaj formatları implementasyonu
 * @details Bu dosya, TCP/UDP/P2P protokolleri için mesaj formatları, şifreleme/şifresizleme,
 *          ve protokol-spesifik gönderim/alma işlemlerinin implementasyonunu içerir.
 *          Her protokol için optimized mesaj formatları ve yanıt mekanizmaları sağlar.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 * @ingroup protocol
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
 * @brief Normal (şifresiz) protokol mesajı oluşturur
 * @details "PARSE:FILENAME:CONTENT" formatında standart protokol mesajı oluşturur.
 *          Bu format sunucu tarafında JSON parse işlemi için kullanılır.
 * 
 * Mesaj Formatı: "PARSE:dosya_adi:json_icerik"
 * 
 * @param filename Gönderilecek dosyanın adı
 * @param content JSON dosya içeriği
 * @return char* Formatlanmış protokol mesajı (NULL: hata)
 * 
 * @note Dönen pointer free() ile serbest bırakılmalıdır
 * @warning filename ve content NULL olmamalıdır
 * 
 * @example
 * @code
 * char* msg = create_normal_protocol_message("data.json", "{\"test\":\"value\"}");
 * // Sonuç: "PARSE:data.json:{\"test\":\"value\"}"
 * @endcode
 */
char* create_normal_protocol_message(const char* filename, const char* content, const char* jwt_token) {
    size_t total_size = strlen("PARSE:") + strlen(filename) + 1 + strlen(content) + 1 + strlen(jwt_token) + 4;
    char *message = malloc(total_size);
    if (message == NULL) {
        PRINTF_LOG("Bellek tahsis hatasi\n");
        return NULL;
    }
    snprintf(message, total_size, "PARSE:%s:%s:%s", filename, content, jwt_token);
    return message;
}

/**
 * @brief Şifreli protokol mesajı oluşturur
 * @details JSON içeriğini AES256 ile şifreleyerek "ENCRYPTED:FILENAME:HEX_DATA" formatında
 *          protokol mesajı oluşturur. Random IV kullanır ve IV+şifreli_veri kombinasyonunu
 *          hex string olarak encode eder.
 * 
 * Şifreleme Süreci:
 * 1. Random IV (16 byte) oluşturma
 * 2. JSON içeriğini AES256-CBC ile şifreleme
 * 3. IV + şifreli_veri birleştirme
 * 4. Binary veriyi hex string'e çevirme
 * 5. "ENCRYPTED:dosya:hex_data" formatında mesaj oluşturma
 * 
 * @param filename Gönderilecek dosyanın adı
 * @param content Şifrelenecek JSON içeriği
 * @param session_key 32 byte AES256 oturum anahtarı (ECDH'den türetilmiş)
 * @return char* Şifreli protokol mesajı (NULL: hata)
 * 
 * @note Dönen pointer free() ile serbest bırakılmalıdır
 * @warning session_key NULL olmamalı ve 32 byte uzunluğunda olmalıdır
 * @warning Her çağrıda farklı IV kullanılır (replay attack koruması)
 * 
 * @example
 * @code
 * uint8_t key[32] = {0}; // ECDH'den alınan anahtar
 * char* encrypted_msg = create_encrypted_protocol_message("data.json", 
 *                                                         "{\"secret\":\"data\"}", key);
 * // Sonuç: "ENCRYPTED:data.json:1a2b3c4d..."
 * @endcode
 */
char* create_encrypted_protocol_message(const char* filename, const char* content, const uint8_t* session_key, const char* jwt_token) {
    if (session_key == NULL) {
        PRINTF_LOG("Session key NULL - şifreleme yapılamaz\n");
        return NULL;
    }
    
    // Random IV olustur
    uint8_t iv[CRYPTO_IV_SIZE];
    generate_random_iv(iv);
    
    PRINTF_LOG("Random IV olusturuldu\n");
    
    // JSON'u sifrele
    crypto_result_t* encrypted = encrypt_data(content, session_key, iv);
    if (encrypted == NULL || !encrypted->success) {
        PRINTF_LOG("Sifreleme hatasi\n");
        if (encrypted) free_crypto_result(encrypted);
        return NULL;
    }
    
    PRINTF_LOG("JSON basariyla sifrelendi (%zu byte)\n", encrypted->length);
    
    // IV + sifreli veri kombinasyonu olustur
    size_t combined_length = CRYPTO_IV_SIZE + encrypted->length;
    uint8_t* combined_data = malloc(combined_length);
    if (combined_data == NULL) {
        PRINTF_LOG("Bellek tahsis hatasi\n");
        free_crypto_result(encrypted);
        return NULL;
    }
    
    memcpy(combined_data, iv, CRYPTO_IV_SIZE);
    memcpy(combined_data + CRYPTO_IV_SIZE, encrypted->data, encrypted->length);
    
    // Hex string'e cevir
    char* hex_data = bytes_to_hex(combined_data, combined_length);
    free(combined_data);
    free_crypto_result(encrypted);
    
    if (hex_data == NULL) {
        PRINTF_LOG("Hex donusumu hatasi\n");
        return NULL;
    }
    
    PRINTF_LOG("Hex encoding tamamlandi (%zu karakter)\n", strlen(hex_data));
    
    // Protokol mesajini olustur
    size_t total_size = strlen("ENCRYPTED:") + strlen(filename) + 1 + strlen(hex_data) + 1 + strlen(jwt_token) + 4;
    char *message = malloc(total_size);
    
    if (message == NULL) {
        PRINTF_LOG("Bellek tahsis hatasi\n");
        free(hex_data);
        return NULL;
    }
    
    snprintf(message, total_size, "ENCRYPTED:%s:%s:%s", filename, hex_data, jwt_token);
    free(hex_data);
    
    return message;
}

/**
 * @brief Client bağlantısını güvenli şekilde kapatır
 * @details Bağlantı kapatma işlemini gerçekleştirir:
 *          1. ECDH context'i temizler (eğer başlatılmışsa)
 *          2. Socket'i kapatır
 *          3. Bellek alanını serbest bırakır
 * 
 * @param conn Kapatılacak client bağlantısı (NULL olabilir)
 * 
 * @note NULL pointer kontrolü yapar, güvenli çağrı
 * @note ECDH context'i otomatik olarak temizlenir
 * @warning Bu fonksiyon çağrıldıktan sonra conn pointer geçersiz olur
 * 
 * @see ecdh_cleanup_context() ECDH temizleme detayları için
 */
void close_connection(client_connection_t* conn) {
    if (conn != NULL) {
        if (conn->ecdh_initialized) {
            ecdh_cleanup_context(&conn->ecdh_ctx);
        }
        if (conn->socket >= 0) {
            close(conn->socket);
        }
        free(conn);
    }
}

/**
 * @brief TCP protokolü ile mesaj gönderir ve yanıt alır
 * @details TCP stream socket üzerinden mesaj gönderir, sunucudan yanıt bekler
 *          ve yanıtı formatlanmış şekilde ekrana yazdırır. Blocking I/O kullanır.
 * 
 * TCP Gönderim Süreci:
 * 1. send() ile mesajı gönder
 * 2. receive_tcp_response() ile yanıt bekle
 * 3. Yanıtı ekrana yazdır
 * 4. Başarı/hata durumu döndür
 * 
 * @param conn TCP bağlantısı (conn->type == CONN_TCP olmalı)
 * @param message Gönderilecek protokol mesajı
 * @return int İşlem sonucu
 * @retval 0 Başarılı gönderim ve yanıt alımı
 * @retval -1 Gönderim hatası, bağlantı kesildi veya yanıt alınamadı
 * 
 * @note TCP reliable protocol olduğu için mesaj kaybı olmaz
 * @warning Büyük mesajlar için partial send durumu kontrol edilmeli
 * 
 * @see receive_tcp_response() TCP yanıt alma detayları
 */
int send_tcp_message(client_connection_t* conn, const char* message) {
    ssize_t bytes_sent = send(conn->socket, message, strlen(message), 0);
    if (bytes_sent < 0) {
        perror("TCP send hatasi");
        return -1;
    }
    PRINTF_LOG("TCP mesaj gonderildi (%zd bytes)\n", bytes_sent);
    
    // Yanıt bekle
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_tcp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        PRINTF_LOG("TCP yanit alindi (%zd bytes)\n", bytes_received);
        PRINTF_LOG("\nServer yaniti:\n");
        PRINTF_LOG("=============\n");
        PRINTF_LOG("%s\n", buffer);
        PRINTF_LOG("=============\n");
        return 0;
    } else if (bytes_received == 0) {
        PRINTF_LOG("TCP baglanti kapatildi\n");
        return -1;
    } else {
        PRINTF_LOG("TCP yanitlama hatasi\n");
        return -1;
    }
}

/**
 * @brief UDP protokolü ile mesaj gönderir ve yanıt alır
 * @details UDP datagram socket üzerinden mesaj gönderir, sunucudan yanıt bekler
 *          ve yanıtı formatlanmış şekilde ekrana yazdırır. Connectionless protokol.
 * 
 * UDP Gönderim Süreci:
 * 1. sendto() ile mesajı belirli adrese gönder
 * 2. receive_udp_response() ile yanıt bekle (timeout ile)
 * 3. Yanıtı ekrana yazdır
 * 4. Başarı/hata durumu döndür
 * 
 * @param conn UDP bağlantısı (conn->type == CONN_UDP olmalı)
 * @param message Gönderilecek protokol mesajı
 * @return int İşlem sonucu
 * @retval 0 Başarılı gönderim ve yanıt alımı
 * @retval -1 Gönderim hatası, timeout veya yanıt alınamadı
 * 
 * @note UDP unreliable protocol - packet loss olabilir
 * @warning Büyük mesajlar fragmente olabilir
 * @note Timeout mekanizması ile yanıt beklenir
 * 
 * @see receive_udp_response() UDP yanıt alma detayları
 */
int send_udp_message(client_connection_t* conn, const char* message) {
    ssize_t bytes_sent = sendto(conn->socket, message, strlen(message), 0,
                               (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr));
    if (bytes_sent < 0) {
        perror("UDP send hatasi");
        return -1;
    }
    PRINTF_LOG("UDP mesaj gonderildi (%zd bytes)\n", bytes_sent);
    
    // Yanıt bekle
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_udp_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        PRINTF_LOG("UDP yanit alindi (%zd bytes)\n", bytes_received);
        PRINTF_LOG("\nServer yaniti:\n");
        PRINTF_LOG("=============\n");
        PRINTF_LOG("%s\n", buffer);
        PRINTF_LOG("=============\n");
        return 0;
    } else if (bytes_received == 0) {
        PRINTF_LOG("UDP baglanti kapatildi\n");
        return -1;
    } else {
        PRINTF_LOG("UDP yanitlama hatasi\n");
        return -1;
    }
}

/**
 * @brief P2P protokolü ile mesaj gönderir ve yanıt alır
 * @details P2P TCP bağlantısı üzerinden özel formatlanmış mesaj gönderir.
 *          Mesajı P2P formatına uyarlayarak sunucuya gönderir ve yanıt bekler.
 * 
 * P2P Mesaj Formatları:
 * - Normal veri: "P2P_DATA:CLIENT_pid:orijinal_mesaj"
 * - Şifreli veri: "P2P_ENCRYPTED:orijinal_mesaj"
 * - Zaten formatlanmış: P2P_ prefix'i varsa direkt gönder
 * 
 * P2P Gönderim Süreci:
 * 1. Mesajı P2P formatına uyarla
 * 2. send() ile formatlanmış mesajı gönder
 * 3. receive_p2p_response() ile yanıt bekle
 * 4. Yanıtı ekrana yazdır
 * 
 * @param conn P2P bağlantısı (conn->type == CONN_P2P olmalı)
 * @param message Gönderilecek protokol mesajı
 * @return int İşlem sonucu
 * @retval 0 Başarılı gönderim ve yanıt alımı
 * @retval -1 Gönderim hatası, bağlantı kesildi veya yanıt alınamadı
 * 
 * @note P2P için özel mesaj formatları kullanılır
 * @note Client PID ile mesaj tanımlaması yapılır
 * @warning P2P mesajları CONFIG_BUFFER_SIZE sınırına tabidir
 * 
 * @see receive_p2p_response() P2P yanıt alma detayları
 */
int send_p2p_message(client_connection_t* conn, const char* message) {
    char p2p_message[CONFIG_BUFFER_SIZE];
    
    // Mesaj zaten P2P formatında mı kontrol et
    if (strncmp(message, "P2P_", 4) == 0) {
        // Mesaj zaten P2P formatında - direkt gönder
        strncpy(p2p_message, message, sizeof(p2p_message) - 1);
        p2p_message[sizeof(p2p_message) - 1] = '\0';
        PRINTF_LOG("P2P formatlanmış mesaj gönderiliyor...\n");
    } else if (strncmp(message, "ENCRYPTED:", 10) == 0) {
        // Şifreli veri için P2P_ENCRYPTED formatında gönder
        snprintf(p2p_message, sizeof(p2p_message), "P2P_ENCRYPTED:%s", message);
        PRINTF_LOG("P2P şifreli mesaj gönderiliyor...\n");
    } else {
        // Normal veri için P2P_DATA formatında gönder
        snprintf(p2p_message, sizeof(p2p_message), "P2P_DATA:CLIENT_%d:%s", 
                 getpid(), message);
        PRINTF_LOG("P2P normal mesaj gönderiliyor...\n");
    }
    
    ssize_t bytes_sent = send(conn->socket, p2p_message, strlen(p2p_message), 0);
    if (bytes_sent < 0) {
        perror("P2P send hatasi");
        return -1;
    }
    PRINTF_LOG("P2P mesaj gonderildi (%zd bytes)\n", bytes_sent);
    
    // Yanıt bekle
    char buffer[CONFIG_BUFFER_SIZE] = {0};
    ssize_t bytes_received = receive_p2p_response(conn, buffer, CONFIG_BUFFER_SIZE - 1);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        PRINTF_LOG("P2P yanit alindi (%zd bytes)\n", bytes_received);
        PRINTF_LOG("\nServer yaniti:\n");
        PRINTF_LOG("=============\n");
        PRINTF_LOG("%s\n", buffer);
        PRINTF_LOG("=============\n");
        return 0;
    } else if (bytes_received == 0) {
        PRINTF_LOG("P2P baglanti kapatildi\n");
        return -1;
    } else {
        PRINTF_LOG("P2P yanitlama hatasi\n");
        return -1;
    }
}

/**
 * @brief TCP bağlantısından yanıt alır
 * @details TCP stream socket'den blocking mode'da yanıt okur.
 *          Buffer overflow koruması sağlar ve null termination ekler.
 * 
 * TCP Alma Süreci:
 * 1. recv() ile veri bekle (blocking)
 * 2. Alınan veri boyutunu kontrol et
 * 3. Buffer'ı null-terminate et
 * 4. Alınan byte sayısını döndür
 * 
 * @param conn TCP bağlantısı
 * @param buffer Yanıtın yazılacağı buffer
 * @param buffer_size Buffer boyutu (null terminator için 1 byte ayrılır)
 * @return int Alınan byte sayısı
 * @retval >0 Başarılı yanıt alımı, alınan byte sayısı
 * @retval -1 Alma hatası veya bağlantı kesildi
 * 
 * @note TCP stream protocol - veri sıralı gelir
 * @warning Buffer overflow koruması için buffer_size-1 kullanılır
 * @note recv() blocking çağrı - timeout ayarlanabilir
 */
int receive_tcp_response(client_connection_t* conn, char* buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(conn->socket, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        perror("TCP receive hatasi");
        return -1;
    } else if (bytes_received == 0) {
        PRINTF_LOG("TCP baglanti kapatildi\n");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    PRINTF_LOG("TCP yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}

/**
 * @brief UDP bağlantısından yanıt alır
 * @details UDP datagram socket'den yanıt okur ve gönderen adres bilgisini alır.
 *          Connectionless protokol olduğu için from_addr kontrolü yapar.
 * 
 * UDP Alma Süreci:
 * 1. recvfrom() ile datagram bekle
 * 2. Gönderen adres bilgisini al
 * 3. Alınan veri boyutunu kontrol et
 * 4. Buffer'ı null-terminate et
 * 5. Alınan byte sayısını döndür
 * 
 * @param conn UDP bağlantısı
 * @param buffer Yanıtın yazılacağı buffer
 * @param buffer_size Buffer boyutu (null terminator için 1 byte ayrılır)
 * @return int Alınan byte sayısı
 * @retval >0 Başarılı yanıt alımı, alınan byte sayısı
 * @retval -1 Alma hatası, timeout veya bağlantı problemi
 * 
 * @note UDP datagram protocol - packet loss olabilir
 * @note Gönderen adres bilgisi from_addr'de saklanır
 * @warning Timeout ayarları socket'de yapılmalıdır
 */
int receive_udp_response(client_connection_t* conn, char* buffer, size_t buffer_size) {
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t bytes_received = recvfrom(conn->socket, buffer, buffer_size - 1, 0,
                                     (struct sockaddr*)&from_addr, &from_len);
    if (bytes_received < 0) {
        perror("UDP receive hatasi");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    PRINTF_LOG("UDP yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}

/**
 * @brief P2P bağlantısından yanıt alır
 * @details P2P TCP stream socket'den yanıt okur. TCP benzeri blocking mode
 *          kullanır ancak P2P protokolüne özel format beklentileri olabilir.
 * 
 * P2P Alma Süreci:
 * 1. recv() ile veri bekle (blocking)
 * 2. Alınan veri boyutunu kontrol et
 * 3. P2P format kontrolü (opsiyonel)
 * 4. Buffer'ı null-terminate et
 * 5. Alınan byte sayısını döndür
 * 
 * @param conn P2P bağlantısı
 * @param buffer Yanıtın yazılacağı buffer
 * @param buffer_size Buffer boyutu (null terminator için 1 byte ayrılır)
 * @return int Alınan byte sayısı
 * @retval >0 Başarılı yanıt alımı, alınan byte sayısı
 * @retval -1 Alma hatası veya bağlantı kesildi
 * 
 * @note P2P TCP tabanlı - reliable data transfer
 * @note Server'dan P2P formatında yanıt beklenir
 * @warning P2P özel format kontrolü eklenebilir
 */
int receive_p2p_response(client_connection_t* conn, char* buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(conn->socket, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        perror("P2P receive hatasi");
        return -1;
    } else if (bytes_received == 0) {
        PRINTF_LOG("P2P baglanti kapatildi\n");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    PRINTF_LOG("P2P yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}
