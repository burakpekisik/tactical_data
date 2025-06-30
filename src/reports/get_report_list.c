#include "get_report_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "config.h"
#include "encrypted_client.h"
#include "logger.h"
#include "protocol_manager.h"

int get_report_list_by_user(client_connection_t* conn, const char* jwt_token) {
    if (!conn->ecdh_initialized) {
        PRINTF_LOG("ECDH başlatılmamış - şifreli rapor listesi alınamaz\n");
        return -1;
    }
    char report_query[2048];
    snprintf(report_query, sizeof(report_query), "{\"command\":\"REPORT_QUERY\",\"jwt\":\"%s\"}", jwt_token);
    char *encrypted_message = create_encrypted_protocol_message("REPORT_QUERY", report_query, conn->ecdh_ctx.aes_key, jwt_token);
    if (!encrypted_message) {
        PRINTF_LOG("Şifreli rapor sorgu mesajı oluşturulamadı\n");
        return -1;
    }
    send(conn->socket, encrypted_message, strlen(encrypted_message), 0);
    free(encrypted_message);

    // --- Parçalı yanıt toplama (stream parsing ile) ---
    char* all_hex_data = NULL;
    size_t all_hex_len = 0;
    int expected_parts = 0, received_parts = 0;
    int done = 0;
    int recv_count = 0;
    char streambuf[65536];
    size_t streambuf_len = 0;
    while (!done) {
        // Eğer streambuf'da yeterli veri yoksa, recv ile tamamla
        if (streambuf_len < 4096) {
            ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
            recv_count++;
            PRINTF_LOG("[CLIENT][RECV] recv_count=%d, pn=%zd\n", recv_count, pn);
            if (pn <= 0) break;
            streambuf_len += pn;
            streambuf[streambuf_len] = '\0';
        }
        // Stream buffer'da ENCRYPTED_PART header'ı ara
        char* header = strstr(streambuf, "ENCRYPTED_PART:");
        if (!header) break;
        char* after_header = header + 15;
        int idx = 0, total = 0;
        size_t plen = 0;
        int n = sscanf(after_header, "%d:%d:%zu:", &idx, &total, &plen);
        if (n != 3) {
            PRINTF_LOG("[CLIENT][PARSE] ENCRYPTED_PART header parse hatası!\n");
            break;
        }
        // Header'ın sonunu bul
        char* hex_start = after_header;
        int colon_count = 0;
        while (*hex_start && colon_count < 3) {
            if (*hex_start == ':') colon_count++;
            hex_start++;
        }
        if (colon_count < 3) {
            PRINTF_LOG("[CLIENT][PARSE] ENCRYPTED_PART header sonu bulunamadı!\n");
            break;
        }
        // Şimdi hex_start'tan itibaren plen kadar hex karakteri almalıyız
        size_t available = streambuf + streambuf_len - hex_start;
        while (available < plen) {
            // Yeterli veri yok, recv ile tamamla
            ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
            recv_count++;
            PRINTF_LOG("[CLIENT][RECV] recv_count=%d, pn=%zd (hex_data tamamlanıyor)\n", recv_count, pn);
            if (pn <= 0) break;
            streambuf_len += pn;
            streambuf[streambuf_len] = '\0';
            available = streambuf + streambuf_len - hex_start;
        }
        // Artık hex_data'nın tamamı buffer'da
        PRINTF_LOG("[CLIENT][PARSE] ENCRYPTED_PART idx=%d/%d, plen=%zu, available=%zu, all_hex_len=%zu\n", idx, total, plen, available, all_hex_len);
        PRINTF_LOG("[CLIENT][PARSE] hex_data ilk 16: %.16s, son 16: %.16s\n", hex_start, hex_start + (plen > 16 ? plen-16 : 0));
        all_hex_data = realloc(all_hex_data, all_hex_len + plen + 1);
        memcpy(all_hex_data + all_hex_len, hex_start, plen);
        all_hex_len += plen;
        all_hex_data[all_hex_len] = '\0';
        received_parts++;
        if (expected_parts == 0) expected_parts = total;
        // Header+hex_data'nın sonrasını streambuf'a kaydır
        size_t consumed = (hex_start - streambuf) + plen;
        memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
        streambuf_len -= consumed;
        streambuf[streambuf_len] = '\0';
        if (received_parts >= expected_parts) { done = 1; break; }
    }
    PRINTF_LOG("[CLIENT][RECV] Tüm parçalar alındı. received_parts=%d, toplam_len=%zu\n", received_parts, all_hex_len);
    if (all_hex_data && all_hex_len > 16) {
        PRINTF_LOG("[CLIENT][HEX2BYTES] all_hex_data toplam uzunluk: %zu\n", all_hex_len);
        PRINTF_LOG("[CLIENT][HEX2BYTES] İlk 64 hex: %.64s\n", all_hex_data);
        if (all_hex_len > 64) PRINTF_LOG("[CLIENT][HEX2BYTES] Son 64 hex: %.64s\n", all_hex_data + all_hex_len - 64);
        size_t encrypted_length;
        PRINTF_LOG("[CLIENT][HEX2BYTES] hex_to_bytes çağrılıyor, input len: %zu\n", strlen(all_hex_data));
        uint8_t* encrypted_bytes = hex_to_bytes(all_hex_data, &encrypted_length);
        PRINTF_LOG("[CLIENT][HEX2BYTES] Byte uzunluğu: %zu\n", encrypted_length);
        if (encrypted_bytes && encrypted_length > 16) {
            uint8_t iv[16];
            memcpy(iv, encrypted_bytes, 16);
            PRINTF_LOG("[CLIENT][DECRYPT] IV (ilk 16 byte):");
            for (int i = 0; i < 16; ++i) PRINTF_LOG("%02x", iv[i]);
            PRINTF_LOG("\n[CLIENT][DECRYPT] Şifreli veri uzunluğu: %zu\n", encrypted_length - 16);
            PRINTF_LOG("[CLIENT][DECRYPT] AES anahtarının ilk 16 byte:");
            for (int i = 0; i < 16; ++i) PRINTF_LOG("%02x", conn->ecdh_ctx.aes_key[i]);
            PRINTF_LOG("\n[CLIENT][DECRYPT] Decrypt fonksiyonu çağrılıyor...\n");
            char* decrypted_json = decrypt_data(
                encrypted_bytes + 16,
                encrypted_length - 16,
                conn->ecdh_ctx.aes_key,
                iv
            );
            if (decrypted_json) {
                PRINTF_CLIENT("\nRapor Listesi (Çözüldü):\n%s\n", decrypted_json);
                PRINTF_LOG("[CLIENT][DECRYPT] Başarılı, toplam uzunluk: %zu\n", strlen(decrypted_json));
                free(decrypted_json);
            } else {
                PRINTF_CLIENT("Rapor listesi şifresi çözülemedi!\n");
                PRINTF_LOG("[CLIENT][DECRYPT] HATA: Decryption başarısız\n");
            }
            free(encrypted_bytes);
        } else {
            PRINTF_CLIENT("Rapor listesi yanıtı hatalı!\n");
            PRINTF_LOG("[CLIENT][DECRYPT] HATA: Yanıt hex_to_bytes başarısız\n");
        }
        free(all_hex_data);
    } else {
        PRINTF_CLIENT("Rapor listesi alınamadı veya bağlantı hatası!\n");
        PRINTF_LOG("[CLIENT][RECV] HATA: all_hex_data yok veya çok kısa\n");
        if (all_hex_data) free(all_hex_data);
    }
    return 1;
}