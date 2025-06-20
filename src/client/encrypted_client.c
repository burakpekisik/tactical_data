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

int main() {
    char filename[CONFIG_MAX_FILENAME];
    int choice;
    
    printf("Encrypted JSON Client - Sifreli dosya gonderme istemcisi\n");
    printf("=======================================================\n");
    
    // Server'a baglan
    client_connection_t* conn = connect_to_server(getenv("SERVER_HOST"));
    if (conn == NULL) {
        return -1;
    }
    
    printf("Server'a basariyla baglandi\n");
    
    while (1) {
        show_menu();
        printf("Seciminiz: ");
        
        if (scanf("%d", &choice) != 1) {
            printf("Gecersiz secim\n");
            while (getchar() != '\n'); // Buffer temizle
            continue;
        }
        
        while (getchar() != '\n'); // Buffer temizle
        
        switch (choice) {
            case 1: // Normal JSON gonder
                printf("JSON dosya adini girin: ");
                if (fgets(filename, CONFIG_MAX_FILENAME, stdin) != NULL) {
                    filename[strcspn(filename, "\n")] = 0; // Newline kaldir
                    if (strlen(filename) > 0) {
                        send_json_file(conn, filename, 0);
                    }
                }
                break;
                
            case 2: // Sifreli JSON gonder
                printf("JSON dosya adini girin: ");
                if (fgets(filename, CONFIG_MAX_FILENAME, stdin) != NULL) {
                    filename[strcspn(filename, "\n")] = 0;
                    if (strlen(filename) > 0) {
                        send_json_file(conn, filename, 1);
                    }
                }
                break;
                
            case 3: // Cikis
                printf("Baglanti kapatiliyor...\n");
                close_connection(conn);
                return 0;
                
            default:
                printf("Gecersiz secim. Lutfen 1-3 arasi bir sayi girin.\n");
                break;
        }
        
        printf("\n");
    }
    
    close_connection(conn);
    return 0;
}

// Menu goster
void show_menu(void) {
    printf("\n=== MENU ===\n");
    printf("1. Normal JSON dosyasi gonder\n");
    printf("2. Sifreli JSON dosyasi gonder\n");
    printf("3. Cikis\n");
    printf("============\n");
}

// Dosya icerigini oku
char* read_file_content(const char* filename, size_t* file_size) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Dosya acilamadi: %s\n", filename);
        return NULL;
    }
    
    // Dosya boyutunu al
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Bellek tahsis et
    char *content = malloc(*file_size + 1);
    if (content == NULL) {
        printf("Bellek tahsis hatasi\n");
        fclose(file);
        return NULL;
    }
    
    // Dosyayi oku
    size_t bytes_read = fread(content, 1, *file_size, file);
    content[bytes_read] = '\0';
    fclose(file);
    
    return content;
}

// JSON dosyasini server'a gonder
int send_json_file(client_connection_t* conn, const char* filename, int encrypt) {
    size_t file_size;
    char *content = read_file_content(filename, &file_size);
    
    if (content == NULL) {
        return -1;
    }
    
    printf("Dosya okundu: %s (%zu byte)\n", filename, file_size);
    
    char *protocol_message;
    if (encrypt) {
        printf("Sifreleme islemi baslatiliyor...\n");
        if (!conn->ecdh_initialized) {
            printf("ECDH başlatılmamış - şifreleme yapılamaz\n");
            free(content);
            return -1;
        }
        protocol_message = create_encrypted_protocol_message(filename, content, conn->ecdh_ctx.aes_key);
    } else {
        printf("Normal gonderim hazırlaniyor...\n");
        protocol_message = create_normal_protocol_message(filename, content);
    }
    
    if (protocol_message == NULL) {
        free(content);
        return -1;
    }
    
    printf("Server'a gonderiliyor...\n");
    
    // İlk olarak mevcut bağlantı türüyle dene
    int result = try_send_message_current_connection(conn, protocol_message);
    
    if (result < 0) {
        printf("Mevcut bağlantı türü (%s) ile gönderim başarısız, fallback deneniyor...\n", 
               get_connection_type_name(conn->type));
        
        // Fallback metodlarını dene
        result = try_send_message_with_fallback(conn, protocol_message, filename, content, encrypt);
    }
    
    if (result < 0) {
        printf("Tüm fallback metodları başarısız\n");
        free(content);
        free(protocol_message);
        return -1;
    }
    
    printf("Basariyla gonderildi\n");
    
    free(content);
    free(protocol_message);
    return 0;
}

// Server yanitini isle
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
        printf("Bilinmeyen baglanti tipi yanit alinamadi\n");
        return;
    }
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("\nServer yaniti:\n");
        printf("=============\n");
        printf("%s\n", buffer);
        printf("=============\n");
    } else if (bytes_received == 0) {
        printf("Server baglantisi kapatildi\n");
    } else {
        printf("Yanitlama hatasi\n");
    }
}

client_connection_t* connect_to_server(const char* server_host) {
    client_connection_t* conn = malloc(sizeof(client_connection_t));
    if (conn == NULL) {
        printf("Bellek tahsis hatasi\n");
        return NULL;
    }
    
    // Connection struct'i başlat
    memset(conn, 0, sizeof(client_connection_t));
    
    if (server_host == NULL) {
        server_host = "127.0.0.1";
    }
    
    printf("Server'a baglaniliyor: %s\n", server_host);
    
    // 1. TCP baglantisi dene (Port: 8080)
    printf("TCP baglantisi deneniyor (Port: %d)...\n", CONFIG_PORT);
    conn->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->socket >= 0) {
        conn->server_addr.sin_family = AF_INET;
        conn->server_addr.sin_port = htons(CONFIG_PORT);
        conn->port = CONFIG_PORT;
        conn->type = CONN_TCP;
        
        // IP adresini çözümle
        if (inet_pton(AF_INET, server_host, &conn->server_addr.sin_addr) <= 0) {
            struct hostent *host_entry = gethostbyname(server_host);
            if (host_entry != NULL) {
                conn->server_addr.sin_addr = *((struct in_addr*)host_entry->h_addr_list[0]);
            } else {
                printf("Host cozumlenemedi: %s\n", server_host);
                close(conn->socket);
                goto try_udp;
            }
        }
        
        // TCP baglantisi dene
        if (connect(conn->socket, (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) == 0) {
            printf("✓ TCP baglantisi basarili (Port: %d)\n", CONFIG_PORT);
            
            // ECDH anahtar değişimi yap
            if (!ecdh_init_context(&conn->ecdh_ctx)) {
                printf("ECDH context başlatılamadı\n");
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
                printf("ECDH anahtar çifti üretilemedi\n");
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Server ile anahtar değişimi
            printf("Server ile anahtar değişimi yapılıyor...\n");
            
            // Server'in public key'ini al
            uint8_t server_public_key[ECC_PUB_KEY_SIZE];
            ssize_t received = recv(conn->socket, server_public_key, ECC_PUB_KEY_SIZE, 0);
            if (received != ECC_PUB_KEY_SIZE) {
                printf("Server public key alınamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Kendi public key'imizi gönder
            ssize_t sent = send(conn->socket, conn->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
            if (sent != ECC_PUB_KEY_SIZE) {
                printf("Public key gönderilemedi\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Shared secret hesapla
            if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
                printf("Shared secret hesaplanamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // AES anahtarını türet
            if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
                printf("AES anahtarı türetilemedi\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            conn->ecdh_initialized = true;
            printf("✓ ECDH anahtar değişimi tamamlandı\n");
            printf("✓ AES256 oturum anahtarı hazır\n");
            
            return conn;
        } else {
            printf("✗ TCP baglantisi basarisiz (Port: %d)\n", CONFIG_PORT);
            close(conn->socket);
        }
    }
    
try_udp:
    // 2. UDP baglantisi dene (Port: 8081)
    printf("UDP baglantisi deneniyor (Port: %d)...\n", CONFIG_UDP_PORT);
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
                printf("Host cozumlenemedi: %s\n", server_host);
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
                printf("✓ UDP baglantisi basarili (Port: %d)\n", CONFIG_UDP_PORT);
                
                // UDP için ECDH anahtar değişimi yap
                if (!ecdh_init_context(&conn->ecdh_ctx)) {
                    printf("UDP ECDH context başlatılamadı\n");
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
                    printf("UDP ECDH anahtar çifti üretilemedi\n");
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Server ile UDP ECDH anahtar değişimi
                printf("UDP Server ile anahtar değişimi yapılıyor...\n");
                
                // ECDH init mesajı gönder
                const char* ecdh_init = "ECDH_INIT";
                if (sendto(conn->socket, ecdh_init, strlen(ecdh_init), 0,
                          (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) < 0) {
                    printf("UDP ECDH init mesajı gönderilemedi\n");
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Server'in public key'ini bekle
                char server_response[1024];
                ssize_t received = recvfrom(conn->socket, server_response, sizeof(server_response) - 1, 0, NULL, 0);
                if (received < 0) {
                    printf("UDP Server public key alınamadı\n");
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                server_response[received] = '\0';
                
                // "ECDH_PUB:" prefix'ini kontrol et
                if (strncmp(server_response, "ECDH_PUB:", 9) != 0) {
                    printf("UDP Geçersiz server response: %s\n", server_response);
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Server public key'ini decode et
                size_t server_key_len;
                uint8_t* server_public_key = hex_to_bytes(server_response + 9, &server_key_len);
                if (server_public_key == NULL || server_key_len != ECC_PUB_KEY_SIZE) {
                    printf("UDP Server public key decode hatası\n");
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
                    printf("UDP Client public key gönderilemedi\n");
                    free(server_public_key);
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // Shared secret hesapla
                if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
                    printf("UDP Shared secret hesaplanamadı\n");
                    free(server_public_key);
                    ecdh_cleanup_context(&conn->ecdh_ctx);
                    close(conn->socket);
                    free(conn);
                    return NULL;
                }
                
                // AES anahtarını türet
                if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
                    printf("UDP AES anahtarı türetilemedi\n");
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
                        printf("✓ UDP ECDH anahtar değişimi tamamlandı\n");
                        printf("✓ UDP AES256 oturum anahtarı hazır\n");
                        return conn;
                    }
                }
                
                printf("UDP ECDH onay mesajı alınamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
        }
        
        printf("✗ UDP baglantisi basarisiz (Port: %d)\n", CONFIG_UDP_PORT);
        close(conn->socket);
    }

try_p2p:
    // 3. P2P baglantisi dene (Port: 8082)
    printf("P2P baglantisi deneniyor (Port: %d)...\n", CONFIG_P2P_PORT);
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
                printf("Host cozumlenemedi: %s\n", server_host);
                close(conn->socket);
                free(conn);
                return NULL;
            }
        }
        
        // P2P TCP baglantisi dene
        if (connect(conn->socket, (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr)) == 0) {
            printf("✓ P2P baglantisi basarili (Port: %d)\n", CONFIG_P2P_PORT);
            
            // P2P için ECDH anahtar değişimi yap (TCP benzeri)
            if (!ecdh_init_context(&conn->ecdh_ctx)) {
                printf("P2P ECDH context başlatılamadı\n");
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            if (!ecdh_generate_keypair(&conn->ecdh_ctx)) {
                printf("P2P ECDH anahtar çifti üretilemedi\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Server ile P2P ECDH anahtar değişimi
            printf("P2P Server ile anahtar değişimi yapılıyor...\n");
            
            // Server'in public key'ini al
            uint8_t server_public_key[ECC_PUB_KEY_SIZE];
            ssize_t received = recv(conn->socket, server_public_key, ECC_PUB_KEY_SIZE, 0);
            if (received != ECC_PUB_KEY_SIZE) {
                printf("P2P Server public key alınamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Kendi public key'imizi gönder
            ssize_t sent = send(conn->socket, conn->ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
            if (sent != ECC_PUB_KEY_SIZE) {
                printf("P2P Public key gönderilemedi\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // Shared secret hesapla
            if (!ecdh_compute_shared_secret(&conn->ecdh_ctx, server_public_key)) {
                printf("P2P Shared secret hesaplanamadı\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            // AES anahtarını türet
            if (!ecdh_derive_aes_key(&conn->ecdh_ctx)) {
                printf("P2P AES anahtarı türetilemedi\n");
                ecdh_cleanup_context(&conn->ecdh_ctx);
                close(conn->socket);
                free(conn);
                return NULL;
            }
            
            conn->ecdh_initialized = true;
            printf("✓ P2P ECDH anahtar değişimi tamamlandı\n");
            printf("✓ P2P AES256 oturum anahtarı hazır\n");
            
            return conn;
        } else {
            printf("✗ P2P baglantisi basarisiz (Port: %d)\n", CONFIG_P2P_PORT);
            close(conn->socket);
        }
    }
    
    printf("✗ Hicbir protokol ile baglanti kurulamadi!\n");
    free(conn);
    return NULL;
}