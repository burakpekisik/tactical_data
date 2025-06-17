#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "crypto_utils.h"

#define PORT 8080
#define BUFFER_SIZE 8192
#define MAX_FILENAME 256

// Function prototypes
char* read_file_content(const char* filename, size_t* file_size);
char* create_normal_protocol_message(const char* filename, const char* content);
char* create_encrypted_protocol_message(const char* filename, const char* content);
int send_json_file(int socket, const char* filename, int encrypt);
void handle_server_response(int socket);
void show_menu(void);

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char filename[MAX_FILENAME];
    int choice;
    
    printf("Encrypted JSON Client - Sifreli dosya gonderme istemcisi\n");
    printf("=======================================================\n");
    
    // Socket olustur
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket olusturma hatasi\n");
        return -1;
    }
    
    // Server adres konfigurasyonu
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Server IP adresini environment variable'dan al (Docker için)
    const char* server_host = getenv("SERVER_HOST");
    if (server_host == NULL) {
        server_host = "127.0.0.1"; // Default localhost
    }
    
    printf("Server'a baglaniliyor: %s:%d\n", server_host, PORT);
    
    // Hostname veya IP adresini çözümle
    struct hostent *host_entry;
    if (inet_pton(AF_INET, server_host, &serv_addr.sin_addr) <= 0) {
        // IP adresi değilse hostname olarak çözümle
        host_entry = gethostbyname(server_host);
        if (host_entry == NULL) {
            printf("Host cozumlenemedi: %s\n", server_host);
            return -1;
        }
        serv_addr.sin_addr = *((struct in_addr*)host_entry->h_addr_list[0]);
    }
    
    // Server'a baglan
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Baglanti hatasi\n");
        printf("Server'in calistiginden emin olun (localhost:%d)\n", PORT);
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
                if (fgets(filename, MAX_FILENAME, stdin) != NULL) {
                    filename[strcspn(filename, "\n")] = 0; // Newline kaldir
                    if (strlen(filename) > 0) {
                        if (send_json_file(sock, filename, 0) == 0) {
                            handle_server_response(sock);
                        }
                    }
                }
                break;
                
            case 2: // Sifreli JSON gonder
                printf("JSON dosya adini girin: ");
                if (fgets(filename, MAX_FILENAME, stdin) != NULL) {
                    filename[strcspn(filename, "\n")] = 0;
                    if (strlen(filename) > 0) {
                        if (send_json_file(sock, filename, 1) == 0) {
                            handle_server_response(sock);
                        }
                    }
                }
                break;
                
            case 3: // Cikis
                printf("Baglanti kapatiliyor...\n");
                close(sock);
                return 0;
                
            default:
                printf("Gecersiz secim. Lutfen 1-3 arasi bir sayi girin.\n");
                break;
        }
        
        printf("\n");
    }
    
    close(sock);
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
int send_json_file(int socket, const char* filename, int encrypt) {
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
    ssize_t sent_bytes = send(socket, protocol_message, strlen(protocol_message), 0);
    if (sent_bytes < 0) {
        printf("Gonderim hatasi\n");
        free(content);
        free(protocol_message);
        return -1;
    }
    
    printf("Basariyla gonderildi (%zd byte)\n", sent_bytes);
    
    free(content);
    free(protocol_message);
    return 0;
}

// Server yanitini isle
void handle_server_response(int socket) {
    char buffer[BUFFER_SIZE] = {0};
    
    ssize_t bytes_received = read(socket, buffer, BUFFER_SIZE - 1);
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
