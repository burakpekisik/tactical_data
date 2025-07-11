#include <stdio.h>
#include "encrypted_client.h"
#include "logger.h"
#include "crypto_utils.h"
#include "protocol_manager.h"
#include "large_response.h"
#include <jwt.h>

// Kullanıcı info stringini döndürür, hata durumunda NULL döner
char* send_info_message(client_connection_t* conn, const char* jwt_token) {
    LOG_SERVER_INFO("[SEND_INFO_MESSAGE] Fonksiyon başladı");
    jwt_t *jwt;
    int decode_result = jwt_decode(&jwt, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    LOG_SERVER_INFO("[SEND_INFO_MESSAGE] jwt_decode result: %d", decode_result);
    if (decode_result != 0) {
        LOG_SERVER_ERROR("[SEND_INFO_MESSAGE] JWT decode başarısız!");
    }

    char cmd_json[1024];
    snprintf(cmd_json, sizeof(cmd_json), "{\"jwt\":\"%s\"}", jwt_token);

    char* protocol_message = create_encrypted_protocol_message("INFO", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        LOG_SERVER_ERROR("[SEND_INFO_MESSAGE] create_encrypted_protocol_message başarısız!");
        return NULL;
    }

    ssize_t sent_bytes = send(conn->socket, protocol_message, strlen(protocol_message), 0);
    LOG_SERVER_INFO("[SEND_INFO_MESSAGE] send() çağrıldı, gönderilen byte: %zd", sent_bytes);
    free(protocol_message);

    // Sunucu yanıtını al ve çöz
    char buffer[16384] = {0};
    ssize_t bytes_received = recv(conn->socket, buffer, sizeof(buffer) - 1, 0);
    LOG_SERVER_INFO("[SEND_INFO_MESSAGE] recv() çağrıldı, alınan byte: %zd", bytes_received);
    if (bytes_received <= 0) {
        PRINTF_CLIENT("INFO yanıtı alınamadı!\n");
        LOG_SERVER_ERROR("[SEND_INFO_MESSAGE] INFO yanıtı alınamadı! bytes_received=%zd", bytes_received);
        return NULL;
    }
    buffer[bytes_received] = '\0';
    PRINTF_CLIENT("[DEBUG] Sunucu yanıtı: %s\n", buffer);
    LOG_SERVER_INFO("[SEND_INFO_MESSAGE] Sunucu yanıtı: %s", buffer);

    char* json_out = malloc(8192);
    if (!json_out) {
        LOG_SERVER_ERROR("[SEND_INFO_MESSAGE] malloc başarısız!");
        return NULL;
    }
    int result = receive_and_decrypt_encrypted_response(buffer, conn->ecdh_ctx.aes_key, json_out, 8192, NULL);
    LOG_SERVER_INFO("[SEND_INFO_MESSAGE] receive_and_decrypt_encrypted_response sonucu: %d", result);
    if (result == 0) {
        PRINTF_CLIENT("[DEBUG] Çözülen JSON: %s\n", json_out);
        LOG_SERVER_INFO("[SEND_INFO_MESSAGE] Çözülen JSON: %s", json_out);
        // Kullanıcı info stringini döndür
        return json_out;
    } else {
        PRINTF_CLIENT("Yanıt çözme hatası!\n");
        LOG_SERVER_ERROR("[SEND_INFO_MESSAGE] Yanıt çözme hatası!");
        free(json_out);
        return NULL;
    }
}

// Qt ile uyumlu: socketten veri okuma Qt tarafında yapılır, sadece şifreli cevabı çözer
// encrypted_response: sunucudan alınan ENCRYPTED yanıt (hex string)
// aes_key: 32 byte anahtar
// out_buf: çözülmüş info stringi (malloc ile ayrılır, çağıran free'ler)
// out_buf_size: out_buf boyutu
// return: 0 = başarı, -1 = hata
int send_info_message_qt(const char* encrypted_response, const uint8_t* aes_key, char** out_buf, size_t out_buf_size) {
    if (!encrypted_response || !aes_key || !out_buf || out_buf_size == 0) {
        PRINTF_CLIENT("[send_info_message_qt] Geçersiz parametre!\n");
        return -1;
    }
    char* json_out = malloc(out_buf_size);
    if (!json_out) {
        PRINTF_CLIENT("[send_info_message_qt] malloc başarısız!\n");
        return -1;
    }
    // Qt'dan gelen veri binary ise, ENCRYPTED:INFO: başlığı ile hex stringe çevir
    size_t binlen = strlen(encrypted_response);
    // UYARI: Qt'dan gelen veri gerçekten binary ise, strlen ile değil parametre ile uzunluk alınmalı!
    // Şimdilik backward compatible olması için strlen kullanıldı, gerekirse parametre eklenmeli.
    char* hexstr = malloc(binlen * 2 + 32);
    if (!hexstr) { free(json_out); return -1; }
    strcpy(hexstr, "ENCRYPTED:INFO:");
    for (size_t i = 0; i < binlen; ++i)
        sprintf(hexstr + 15 + i * 2, "%02x", (unsigned char)encrypted_response[i]);
    int result = receive_and_decrypt_encrypted_response(hexstr, aes_key, json_out, out_buf_size, NULL);
    free(hexstr);
    if (result == 0) {
        *out_buf = json_out;
        PRINTF_CLIENT("[send_info_message_qt] Çözülen JSON: %s\n", json_out);
        return 0;
    } else {
        free(json_out);
        PRINTF_CLIENT("[send_info_message_qt] Yanıt çözme hatası!\n");
        return -1;
    }
}
