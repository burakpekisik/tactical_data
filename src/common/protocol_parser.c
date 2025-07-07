#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Protokol mesajını parse eder - "COMMAND:FILENAME:CONTENT" formatı
 * @ingroup server
 * 
 * Client'tan gelen protokol mesajını üç parçaya ayırır: komut, dosya adı ve içerik.
 * Sunucu protokolü gereği mesajlar ":" karakteri ile ayrılmış olmalıdır.
 * 
 * Protokol formatı:
 * - PARSE:filename.json:{"unit":"data"}
 * - ENCRYPTED:filename.json:48656c6c6f576f726c64
 * - CONTROL:command_name:parameters
 * 
 * @param message Parse edilecek protokol mesajı
 * @param command Output: Komut string'i (malloc'lu)
 * @param filename Output: Dosya adı string'i (malloc'lu)
 * @param content Output: İçerik string'i (malloc'lu)
 * 
 * @return 0 başarılı parse işlemi
 * @return -1 format hatası veya bellek ayırma hatası
 * 
 * @note Başarılı parse'da tüm output parametreleri malloc'lu string'ler olur.
 *       Caller bu string'leri free etmekle yükümlüdür.
 * 
 * @warning Hata durumunda kısmen ayrılan bellek otomatik temizlenir.
 *          Output parametreleri başarısızlıkta güvenilir değildir.
 * 
 * Örnekler:
 * @code
 * char *cmd, *file, *content;
 * 
 * // Başarılı parse
 * int result = parse_protocol_message("PARSE:data.json:{}", &cmd, &file, &content);
 * if (result == 0) {
 *     // cmd = "PARSE", file = "data.json", content = "{}"
 *     free(cmd); free(file); free(content);
 * }
 * 
 * // Geçersiz format
 * int result = parse_protocol_message("invalid_format", &cmd, &file, &content);
 * // result = -1, output parametreleri güvenilir değil
 * @endcode
 */
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

// ENCRYPTED mesajı için 4 alanı ayır
int parse_encrypted_protocol_message(const char* message, char** command, char** filename, char** hex_data, char** jwt_token) {
    printf("[PROTOCOL][DEBUG] parse_encrypted_protocol_message: raw message: '%s'\n", message);
    // Trim baştaki ve sondaki boşluk, \n, \r karakterlerini kaldır
    size_t msglen = strlen(message);
    while (msglen > 0 && (message[msglen-1] == '\n' || message[msglen-1] == '\r' || message[msglen-1] == ' ')) msglen--;
    char* trimmed = strndup(message, msglen);
    // printf("[PROTOCOL][DEBUG] trimmed message: '%s'\n", trimmed);
    char* first_colon = strchr(trimmed, ':');
    if (!first_colon) { printf("[PROTOCOL][ERROR] 1. ':' bulunamadı, gelen: '%s'\n", trimmed); free(trimmed); return -1; }
    char* second_colon = strchr(first_colon + 1, ':');
    if (!second_colon) { printf("[PROTOCOL][ERROR] 2. ':' bulunamadı, gelen: '%s'\n", trimmed); free(trimmed); return -1; }
    char* third_colon = strchr(second_colon + 1, ':');
    if (!third_colon) { printf("[PROTOCOL][ERROR] 3. ':' bulunamadı, gelen: '%s'\n", trimmed); free(trimmed); return -1; }
    size_t command_length = first_colon - trimmed;
    size_t filename_length = second_colon - first_colon - 1;
    size_t hex_length = third_colon - second_colon - 1;
    size_t jwt_length = strlen(third_colon + 1);
    *command = malloc(command_length + 1);
    *filename = malloc(filename_length + 1);
    *hex_data = malloc(hex_length + 1);
    *jwt_token = malloc(jwt_length + 1);
    if (!*command || !*filename || !*hex_data || !*jwt_token) {
        printf("[PROTOCOL][ERROR] malloc başarısız (command_len=%zu, filename_len=%zu, hex_len=%zu, jwt_len=%zu)\n", command_length, filename_length, hex_length, jwt_length);
        if (*command) free(*command);
        if (*filename) free(*filename);
        if (*hex_data) free(*hex_data);
        if (*jwt_token) free(*jwt_token);
        free(trimmed);
        return -1;
    }
    strncpy(*command, trimmed, command_length); (*command)[command_length] = '\0';
    strncpy(*filename, first_colon + 1, filename_length); (*filename)[filename_length] = '\0';
    strncpy(*hex_data, second_colon + 1, hex_length); (*hex_data)[hex_length] = '\0';
    strcpy(*jwt_token, third_colon + 1);
    printf("[PROTOCOL][DEBUG] command='%s', filename='%s', hex_data-len=%zu, jwt_token='%s'\n", *command, *filename, strlen(*hex_data), *jwt_token);
    free(trimmed);
    return 0;
}