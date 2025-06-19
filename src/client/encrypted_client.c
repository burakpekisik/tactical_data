#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "crypto_utils.h"
#include "config.h"

// Connection types
typedef enum {
    CONN_TCP = 0,
    CONN_UDP = 1,
    CONN_P2P = 2
} connection_type_t;

typedef struct {
    int socket;
    connection_type_t type;
    int port;
    struct sockaddr_in server_addr;
} client_connection_t;

// Function prototypes
char* read_file_content(const char* filename, size_t* file_size);
char* create_normal_protocol_message(const char* filename, const char* content);
char* create_encrypted_protocol_message(const char* filename, const char* content);
int send_json_file(client_connection_t* conn, const char* filename, int encrypt);
void handle_server_response(client_connection_t* conn);
void show_menu(void);
client_connection_t* connect_to_server(const char* server_host);
void close_connection(client_connection_t* conn);
int send_tcp_message(client_connection_t* conn, const char* message);
int send_udp_message(client_connection_t* conn, const char* message);
int send_p2p_message(client_connection_t* conn, const char* message);
int receive_tcp_response(client_connection_t* conn, char* buffer, size_t buffer_size);
int receive_udp_response(client_connection_t* conn, char* buffer, size_t buffer_size);
int receive_p2p_response(client_connection_t* conn, char* buffer, size_t buffer_size);

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
                        if (send_json_file(conn, filename, 0) == 0) {
                            handle_server_response(conn);
                        }
                    }
                }
                break;
                
            case 2: // Sifreli JSON gonder
                printf("JSON dosya adini girin: ");
                if (fgets(filename, CONFIG_MAX_FILENAME, stdin) != NULL) {
                    filename[strcspn(filename, "\n")] = 0;
                    if (strlen(filename) > 0) {
                        if (send_json_file(conn, filename, 1) == 0) {
                            handle_server_response(conn);
                        }
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

// Normal protokol mesajini olustur: "PARSE:FILENAME:CONTENT"
char* create_normal_protocol_message(const char* filename, const char* content) {
    size_t total_size = strlen("PARSE:") + strlen(filename) + strlen(content) + 2;
    char *message = malloc(total_size);
    
    if (message == NULL) {
        printf("Bellek tahsis hatasi\n");
        return NULL;
    }
    
    snprintf(message, total_size, "PARSE:%s:%s", filename, content);
    return message;
}

// Sifreli protokol mesajini olustur: "ENCRYPTED:FILENAME:HEX_DATA"
char* create_encrypted_protocol_message(const char* filename, const char* content) {
    // Random IV olustur
    uint8_t iv[CRYPTO_IV_SIZE];
    generate_random_iv(iv);
    
    printf("Random IV olusturuldu\n");
    
    // JSON'u sifrele
    crypto_result_t* encrypted = encrypt_data(content, NULL, iv);
    if (encrypted == NULL || !encrypted->success) {
        printf("Sifreleme hatasi\n");
        if (encrypted) free_crypto_result(encrypted);
        return NULL;
    }
    
    printf("JSON basariyla sifrelendi (%zu byte)\n", encrypted->length);
    
    // IV + sifreli veri kombinasyonu olustur
    size_t combined_length = CRYPTO_IV_SIZE + encrypted->length;
    uint8_t* combined_data = malloc(combined_length);
    if (combined_data == NULL) {
        printf("Bellek tahsis hatasi\n");
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
        printf("Hex donusumu hatasi\n");
        return NULL;
    }
    
    printf("Hex encoding tamamlandi (%zu karakter)\n", strlen(hex_data));
    
    // Protokol mesajini olustur
    size_t total_size = strlen("ENCRYPTED:") + strlen(filename) + strlen(hex_data) + 3;
    char *message = malloc(total_size);
    
    if (message == NULL) {
        printf("Bellek tahsis hatasi\n");
        free(hex_data);
        return NULL;
    }
    
    snprintf(message, total_size, "ENCRYPTED:%s:%s", filename, hex_data);
    free(hex_data);
    
    return message;
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
        protocol_message = create_encrypted_protocol_message(filename, content);
    } else {
        printf("Normal gonderim hazırlaniyor...\n");
        protocol_message = create_normal_protocol_message(filename, content);
    }
    
    if (protocol_message == NULL) {
        free(content);
        return -1;
    }
    
    printf("Server'a gonderiliyor...\n");
    
    // Mesaji gonder
    int result;
    if (conn->type == CONN_TCP) {
        result = send_tcp_message(conn, protocol_message);
    } else if (conn->type == CONN_UDP) {
        result = send_udp_message(conn, protocol_message);
    } else if (conn->type == CONN_P2P) {
        result = send_p2p_message(conn, protocol_message);
    } else {
        printf("Bilinmeyen baglanti tipi\n");
        result = -1;
    }
    
    if (result < 0) {
        printf("Gonderim hatasi\n");
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

// Server connection with fallback (TCP -> UDP)
client_connection_t* connect_to_server(const char* server_host) {
    client_connection_t* conn = malloc(sizeof(client_connection_t));
    if (conn == NULL) {
        printf("Bellek tahsis hatasi\n");
        return NULL;
    }
    
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
                return conn;
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

// Baglantiyi kapat
void close_connection(client_connection_t* conn) {
    if (conn != NULL) {
        if (conn->socket >= 0) {
            close(conn->socket);
        }
        free(conn);
    }
}

// TCP mesaj gonder
int send_tcp_message(client_connection_t* conn, const char* message) {
    ssize_t bytes_sent = send(conn->socket, message, strlen(message), 0);
    if (bytes_sent < 0) {
        perror("TCP send hatasi");
        return -1;
    }
    printf("TCP mesaj gonderildi (%zd bytes)\n", bytes_sent);
    return 0;
}

// UDP mesaj gonder
int send_udp_message(client_connection_t* conn, const char* message) {
    ssize_t bytes_sent = sendto(conn->socket, message, strlen(message), 0,
                               (struct sockaddr*)&conn->server_addr, sizeof(conn->server_addr));
    if (bytes_sent < 0) {
        perror("UDP send hatasi");
        return -1;
    }
    printf("UDP mesaj gonderildi (%zd bytes)\n", bytes_sent);
    return 0;
}

// P2P mesaj gonder
int send_p2p_message(client_connection_t* conn, const char* message) {
    // P2P protokolu: P2P_DATA:NODE_ID:MESSAGE
    char p2p_message[CONFIG_BUFFER_SIZE];
    snprintf(p2p_message, sizeof(p2p_message), "P2P_DATA:CLIENT_%d:%s", 
             getpid(), message);
    
    ssize_t bytes_sent = send(conn->socket, p2p_message, strlen(p2p_message), 0);
    if (bytes_sent < 0) {
        perror("P2P send hatasi");
        return -1;
    }
    printf("P2P mesaj gonderildi (%zd bytes)\n", bytes_sent);
    return 0;
}

// TCP yanit al
int receive_tcp_response(client_connection_t* conn, char* buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(conn->socket, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        perror("TCP receive hatasi");
        return -1;
    } else if (bytes_received == 0) {
        printf("TCP baglanti kapatildi\n");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    printf("TCP yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}

// UDP yanit al
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
    printf("UDP yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}

// P2P yanit al
int receive_p2p_response(client_connection_t* conn, char* buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(conn->socket, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        perror("P2P receive hatasi");
        return -1;
    } else if (bytes_received == 0) {
        printf("P2P baglanti kapatildi\n");
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    printf("P2P yanit alindi (%zd bytes)\n", bytes_received);
    return bytes_received;
}
