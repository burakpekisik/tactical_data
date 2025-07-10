#include <stdio.h>
#include "encrypted_client.h"
#include "logger.h"
#include "crypto_utils.h"
#include "protocol_manager.h"
#include "large_response.h"
#include <jwt.h>

int send_info_message(client_connection_t* conn, const char* jwt_token) {
    jwt_t *jwt;
    int decode_result = jwt_decode(&jwt, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    LOG_SERVER_INFO("[SEND_INFO_MESSAGE] jwt_decode result: %d", decode_result);

    char cmd_json[1024];
    snprintf(cmd_json, sizeof(cmd_json), "{\"jwt\":\"%s\"}", jwt_token);

    char* protocol_message = create_encrypted_protocol_message("INFO", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return -1;
    }

    send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);

    // Sunucu yanıtını al ve çöz
    char buffer[16384] = {0};
    ssize_t bytes_received = recv(conn->socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        PRINTF_CLIENT("INFO yanıtı alınamadı!\n");
        return -1;
    }
    buffer[bytes_received] = '\0';
    PRINTF_CLIENT("[DEBUG] Sunucu yanıtı: %s\n", buffer);

    char json_out[8192];
    int result = receive_and_decrypt_encrypted_response(buffer, conn->ecdh_ctx.aes_key, json_out, sizeof(json_out), NULL);
    if (result == 0) {
        PRINTF_CLIENT("[DEBUG] Çözülen JSON: %s\n", json_out);
    } else {
        PRINTF_CLIENT("Yanıt çözme hatası!\n");
        return -1;
    }

    return 0;
}
