#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "crypto_utils.h"
#include "json_utils.h"

#define PORT 8080
#define BUFFER_SIZE 8192
#define MAX_CLIENTS 10

// Function prototypes
int parse_protocol_message(const char* message, char** command, char** filename, char** content);
void handle_client(int client_socket);
char* handle_encrypted_request(const char* filename, const char* encrypted_content);

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    printf("Encrypted JSON Server - Sifreli dosya parse sunucusu\n");
    printf("===================================================\n");
    fflush(stdout);
    
    // Socket olustur
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket olusturma hatasi");
        exit(EXIT_FAILURE);
    }
    
    // Socket secenekleri
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt hatasi");
        exit(EXIT_FAILURE);
    }
    
    // Adres konfigurasyonu
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Socket'i porta bagla
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind hatasi");
        exit(EXIT_FAILURE);
    }
    
    // Dinlemeye basla
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen hatasi");
        exit(EXIT_FAILURE);
    }
    
    printf("Server baslatildi\n");
    printf("Port %d'de sifreli JSON parse istekleri bekleniyor...\n", PORT);
    printf("Desteklenen komutlar:\n");
    printf("  PARSE:filename:{json_data}      - Normal JSON parse\n");
    printf("  ENCRYPTED:filename:{hex_data}   - Sifreli JSON parse\n");
    printf("Cikis icin Ctrl+C'ye basin\n\n");
    fflush(stdout);
    
    while (1) {
        printf("Yeni baglanti bekleniyor...\n");
        fflush(stdout);
        
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept hatasi");
            continue;
        }
        
        printf("Yeni client baglandi: %s:%d\n", 
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));
        fflush(stdout);
        
        handle_client(new_socket);
        close(new_socket);
        printf("Client baglantisi kapatildi\n\n");
        fflush(stdout);
    }
    
    close(server_fd);
    return 0;
}

// Client ile iletisimi yonet
void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        
        ssize_t bytes_received = read(client_socket, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            printf("Client baglantisi kesildi\n");
            fflush(stdout);
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        char *current_time = get_current_time();
        printf("[%s] Mesaj alindi (%zd byte)\n", current_time, bytes_received);
        fflush(stdout);
        free(current_time);
        
        // Protokol mesajini parse et
        char *command = NULL;
        char *filename = NULL;
        char *content = NULL;
        
        if (parse_protocol_message(buffer, &command, &filename, &content) != 0) {
            char *error_response = "HATA: Gecersiz protokol formati. Format: COMMAND:FILENAME:CONTENT";
            send(client_socket, error_response, strlen(error_response), 0);
            continue;
        }
        
        printf("Komut: %s\n", command);
        printf("Dosya: %s\n", filename);
        fflush(stdout);
        
        char *parsed_result = NULL;
        
        // Komut tipine gore islem yap
        if (strcmp(command, "PARSE") == 0) {
            printf("Normal JSON parse ediliyor...\n");
            fflush(stdout);
            parsed_result = parse_json_to_string(content, filename);
        } else if (strcmp(command, "ENCRYPTED") == 0) {
            printf("Sifreli JSON parse ediliyor...\n");
            fflush(stdout);
            parsed_result = handle_encrypted_request(filename, content);
        } else {
            parsed_result = malloc(256);
            snprintf(parsed_result, 256, "HATA: Bilinmeyen komut: %s", command);
        }
        
        // Sonucu client'a gonder
        if (parsed_result != NULL) {
            send(client_socket, parsed_result, strlen(parsed_result), 0);
            printf("Parse sonucu gonderildi\n");
            fflush(stdout);
            free(parsed_result);
        }
        
        // Bellek temizligi
        free(command);
        free(filename);
        free(content);
    }
}

// Sifreli istek ile bas et
char* handle_encrypted_request(const char* filename, const char* encrypted_content) {
    // Hex string'i bytes'a cevir
    size_t encrypted_length;
    uint8_t* encrypted_bytes = hex_to_bytes(encrypted_content, &encrypted_length);
    
    if (encrypted_bytes == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Gecersiz hex format");
        return error_msg;
    }
    
    // IV'yi ayikla (ilk 16 byte)
    if (encrypted_length < CRYPTO_IV_SIZE) {
        free(encrypted_bytes);
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Yetersiz veri boyutu (IV eksik)");
        return error_msg;
    }
    
    uint8_t iv[CRYPTO_IV_SIZE];
    memcpy(iv, encrypted_bytes, CRYPTO_IV_SIZE);
    
    // Sifreli veriyi decrypt et
    char* decrypted_json = decrypt_data(
        encrypted_bytes + CRYPTO_IV_SIZE,
        encrypted_length - CRYPTO_IV_SIZE,
        NULL, // Default key kullan
        iv
    );
    
    free(encrypted_bytes);
    
    if (decrypted_json == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Decryption basarisiz");
        return error_msg;
    }
    
    printf("Decrypted JSON: %s\n", decrypted_json);
    
    // JSON'u parse et
    char* result = parse_json_to_string(decrypted_json, filename);
    free(decrypted_json);
    
    return result;
}

// Protokol mesajini parse et: "COMMAND:FILENAME:CONTENT"
int parse_protocol_message(const char* message, char** command, char** filename, char** content) {
    char* first_colon = strchr(message, ':');
    if (first_colon == NULL) {
        return -1;
    }
    
    char* second_colon = strchr(first_colon + 1, ':');
    if (second_colon == NULL) {
        return -1;
    }
    
    size_t command_length = first_colon - message;
    size_t filename_length = second_colon - first_colon - 1;
    size_t content_length = strlen(second_colon + 1);
    
    *command = malloc(command_length + 1);
    *filename = malloc(filename_length + 1);
    *content = malloc(content_length + 1);
    
    if (*command == NULL || *filename == NULL || *content == NULL) {
        if (*command) free(*command);
        if (*filename) free(*filename);
        if (*content) free(*content);
        return -1;
    }
    
    strncpy(*command, message, command_length);
    (*command)[command_length] = '\0';
    
    strncpy(*filename, first_colon + 1, filename_length);
    (*filename)[filename_length] = '\0';
    
    strcpy(*content, second_colon + 1);
    
    return 0;
}


