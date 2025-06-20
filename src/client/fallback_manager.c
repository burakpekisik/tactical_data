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

// Bağlantı türü adını al
const char* get_connection_type_name(connection_type_t type) {
    switch (type) {
        case CONN_TCP: return "TCP";
        case CONN_UDP: return "UDP";
        case CONN_P2P: return "P2P";
        default: return "UNKNOWN";
    }
}

// Mevcut bağlantı türüyle mesaj göndermeyi dene
int try_send_message_current_connection(client_connection_t* conn, const char* message) {
    int result = -1;
    
    if (conn->type == CONN_TCP) {
        result = send_tcp_message(conn, message);
    } else if (conn->type == CONN_UDP) {
        result = send_udp_message(conn, message);
    } else if (conn->type == CONN_P2P) {
        result = send_p2p_message(conn, message);
    } else {
        printf("Bilinmeyen baglanti tipi\n");
    }
    
    return result;
}

// Fallback ile mesaj göndermeyi dene
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
        printf("Fallback deneniyor: %s\n", get_connection_type_name(fallback_type));
        
        // Yeni bağlantı tipi için socket oluştur ve bağlan
        client_connection_t* fallback_conn = create_fallback_connection(conn, fallback_type);
        if (fallback_conn == NULL) {
            printf("Fallback bağlantı oluşturulamadı: %s\n", get_connection_type_name(fallback_type));
            continue;
        }
        
        // Fallback bağlantısı için protokol mesajını yeniden oluştur
        char* fallback_message = NULL;
        
        // Şifreli mesaj mı kontrol et
        if (encrypt && strncmp(protocol_message, "ENCRYPTED:", 10) == 0) {
            // Şifreli mesaj için yeni ECDH anahtarıyla yeniden şifrele
            printf("Fallback için JSON yeniden şifreleniyor...\n");
            
            if (!fallback_conn->ecdh_initialized) {
                printf("Fallback ECDH başlatılmamış - şifreleme yapılamaz\n");
                close_connection(fallback_conn);
                continue;
            }
            
            // Yeni anahtar ile yeniden şifrele
            fallback_message = create_encrypted_protocol_message(filename, content, fallback_conn->ecdh_ctx.aes_key);
            if (fallback_message == NULL) {
                printf("Fallback şifreleme başarısız\n");
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
            printf("✓ Fallback başarılı: %s\n", get_connection_type_name(fallback_type));
            
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
        
        printf("✗ Fallback başarısız: %s\n", get_connection_type_name(fallback_type));
        
        // Fallback bağlantısını temizle
        close_connection(fallback_conn);
        
        // Mesajı temizle (eğer yeniden oluşturulmuşsa)
        if (fallback_message != protocol_message && fallback_message != NULL) {
            free(fallback_message);
        }
    }
    
    return -1; // Tüm fallback'ler başarısız
}

// Fallback bağlantısı oluştur
client_connection_t* create_fallback_connection(client_connection_t* original_conn, connection_type_t target_type) {
    client_connection_t* fallback_conn = malloc(sizeof(client_connection_t));
    if (fallback_conn == NULL) {
        printf("Fallback connection için bellek tahsis hatası\n");
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
            printf("Geçersiz fallback connection tipi\n");
            free(fallback_conn);
            return NULL;
    }
    
    fallback_conn->port = port;
    fallback_conn->server_addr.sin_port = htons(port);
    
    // Socket oluştur
    fallback_conn->socket = socket(AF_INET, sock_type, 0);
    if (fallback_conn->socket < 0) {
        printf("Fallback socket oluşturulamadı\n");
        free(fallback_conn);
        return NULL;
    }
    
    // Bağlantı kur
    if (target_type == CONN_TCP || target_type == CONN_P2P) {
        // TCP/P2P için connect
        if (connect(fallback_conn->socket, (struct sockaddr*)&fallback_conn->server_addr, 
                   sizeof(fallback_conn->server_addr)) < 0) {
            printf("Fallback %s bağlantısı kurulamadı\n", get_connection_type_name(target_type));
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
        
        // ECDH key exchange (TCP ve P2P için)
        if (!setup_ecdh_for_fallback(fallback_conn)) {
            printf("Fallback ECDH kurulumu başarısız\n");
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
        
    } else if (target_type == CONN_UDP) {
        // UDP için test ping
        const char* test_msg = "PING";
        if (sendto(fallback_conn->socket, test_msg, strlen(test_msg), 0,
                   (struct sockaddr*)&fallback_conn->server_addr, sizeof(fallback_conn->server_addr)) <= 0) {
            printf("Fallback UDP test ping gönderilemedi\n");
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
            printf("Fallback UDP test response alınamadı\n");
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
        
        // UDP ECDH setup
        if (!setup_udp_ecdh_for_fallback(fallback_conn)) {
            printf("Fallback UDP ECDH kurulumu başarısız\n");
            close(fallback_conn->socket);
            free(fallback_conn);
            return NULL;
        }
    }
    
    printf("✓ Fallback bağlantı kuruldu: %s (Port: %d)\n", 
           get_connection_type_name(target_type), port);
    
    return fallback_conn;
}

// TCP/P2P için ECDH kurulumu
bool setup_ecdh_for_fallback(client_connection_t* conn) {
    if (!ecdh_init_context(&conn->ecdh_ctx)) {
        printf("Fallback ECDH context başlatılamadı\n");
        return false;
    }
    
    if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
        printf("Fallback ECDH anahtar çifti üretilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Server'in public key'ini al
    uint8_t server_public_key[ECC_PUB_KEY_SIZE];
    ssize_t received = recv(conn->socket, server_public_key, ECC_PUB_KEY_SIZE, 0);
    if (received != ECC_PUB_KEY_SIZE) {
        printf("Fallback Server public key alınamadı\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Kendi public key'imizi gönder
    ssize_t sent = send(conn->socket, conn->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
    if (sent != ECC_PUB_KEY_SIZE) {
        printf("Fallback Public key gönderilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Shared secret hesapla
    if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
        printf("Fallback Shared secret hesaplanamadı\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // AES anahtarını türet
    if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
        printf("Fallback AES anahtarı türetilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    conn->ecdh_initialized = true;
    printf("✓ Fallback ECDH anahtar değişimi tamamlandı\n");
    return true;
}

// UDP için ECDH kurulumu
bool setup_udp_ecdh_for_fallback(client_connection_t* conn) {
    if (!ecdh_init_context(&conn->ecdh_ctx)) {
        printf("Fallback UDP ECDH context başlatılamadı\n");
        return false;
    }
    
    if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
        printf("Fallback UDP ECDH anahtar çifti üretilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // ECDH init mesajı gönder
    const char* ecdh_init = "ECDH_INIT";
    if (sendto(conn->socket, ecdh_init, strlen(ecdh_init), 0,
              (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) < 0) {
        printf("Fallback UDP ECDH init mesajı gönderilemedi\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Server'in public key'ini bekle
    char server_response[1024];
    ssize_t received = recvfrom(conn->socket, server_response, sizeof(server_response) - 1, 0, NULL, 0);
    if (received < 0) {
        printf("Fallback UDP Server public key alınamadı\n");
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    server_response[received] = '\0';
    
    // "ECDH_PUB:" prefix'ini kontrol et
    if (strncmp(server_response, "ECDH_PUB:", 9) != 0) {
        printf("Fallback UDP Geçersiz server response: %s\n", server_response);
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Server public key'ini decode et
    size_t server_key_len;
    uint8_t* server_public_key = hex_to_bytes(server_response + 9, &server_key_len);
    if (server_public_key == NULL || server_key_len != ECC_PUB_KEY_SIZE) {
        printf("Fallback UDP Server public key decode hatası\n");
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
        printf("Fallback UDP Client public key gönderilemedi\n");
        free(server_public_key);
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // Shared secret hesapla
    if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
        printf("Fallback UDP Shared secret hesaplanamadı\n");
        free(server_public_key);
        ecdh_cleanup_context(&conn->ecdh_ctx);
        return false;
    }
    
    // AES anahtarını türet
    if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
        printf("Fallback UDP AES anahtarı türetilemedi\n");
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
            printf("✓ Fallback UDP ECDH anahtar değişimi tamamlandı\n");
            return true;
        }
    }
    
    printf("Fallback UDP ECDH onay mesajı alınamadı\n");
    ecdh_cleanup_context(&conn->ecdh_ctx);
    return false;
}

// Mesajı protokol tipine göre uyarla
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
