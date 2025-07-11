#include "encrypted_client.h"
#include <stdio.h>
#include <stdlib.h>
#include "logger.h"
#include "protocol_manager.h"

void query_replies_to_one_report(client_connection_t* conn, const char* jwt_token) {
    if (!conn || !jwt_token || strlen(jwt_token) == 0) {
        PRINTF_CLIENT("JWT token veya bağlantı hatalı!\n");
        return;
    }
    if (!conn->ecdh_initialized) {
        PRINTF_CLIENT("ECDH başlatılmamış - şifreli sorgu yapılamaz!\n");
        return;
    }
    
    PRINTF_LOG("[CLIENT][QUERY_REPLIES_ONE_REPORT] Rapora gelen cevapları sorgulama başlatılıyor...\n");
    
    printf("Lütfen rapor ID'sini girin: ");
    int report_id;
    scanf("%d", &report_id);

    // JSON komutu oluştur
    char cmd_json[2048];
    snprintf(cmd_json, sizeof(cmd_json), "{\"report_id\":%d,\"jwt\":\"%s\"}", report_id, jwt_token);
    
    // QUERY_MY_REPLIES komutu şifrele ve gönder
    char* protocol_message = create_encrypted_protocol_message("QUERY_REPLIES_ONE_REPORT", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }
    
    // Mesajı socket'a direkt gönder
    ssize_t bytes_sent = send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);
    if (bytes_sent < 0) {
        PRINTF_CLIENT("Şifreli sorgu gönderilemedi!\n");
        return;
    }
    
    PRINTF_LOG("QUERY_REPLIES_ONE_REPORT komutu gönderildi (%zd bytes), yanıt bekleniyor...\n", bytes_sent);
    
    // --- Parçalı yanıt toplama (QUERY_REPLIES_ONE_REPORT için) ---
    char* all_hex_data = NULL;
    size_t all_hex_len = 0;
    int recv_count = 0;
    int done = 0;
    char streambuf[65536];
    size_t streambuf_len = 0;
    
    while (!done) {
        // Eğer streambuf'da yeterli veri yoksa, recv ile tamamla
        if (streambuf_len < 4096) {
            ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
            recv_count++;
            PRINTF_LOG("[CLIENT][RECV] recv_count=%d, bytes_received=%zd, buffer_len=%zu\n", recv_count, pn, streambuf_len);
            if (pn <= 0) {
                PRINTF_LOG("[CLIENT][RECV] recv hatası veya bağlantı kapatıldı: %zd\n", pn);
                break;
            }
            streambuf_len += pn;
            streambuf[streambuf_len] = '\0';
            PRINTF_LOG("[CLIENT][RECV] Toplam buffer: %zu bytes\n", streambuf_len);
        }
        
        // ENCRYPTED:QUERY_REPLIES_ONE_REPORT: formatı kontrol et (tek parça encrypted)
        const char* single_encrypted_prefix = "ENCRYPTED:QUERY_REPLIES_ONE_REPORT:";
        if (strncmp(streambuf, single_encrypted_prefix, strlen(single_encrypted_prefix)) == 0) {
            const char* hex_data = streambuf + strlen(single_encrypted_prefix);
            char* newline = strchr(hex_data, '\n');
            size_t hex_len;
            
            if (newline) {
                hex_len = newline - hex_data;
            } else {
                hex_len = strlen(hex_data);
                if (hex_len > 0 && hex_data[hex_len-1] == '\n') {
                    hex_len--;
                }
            }
            
            PRINTF_LOG("[CLIENT][SINGLE_ENC] Hex veri uzunluğu: %zu\n", hex_len);
            
            if (hex_len > 0) {
                all_hex_data = malloc(hex_len + 1);
                memcpy(all_hex_data, hex_data, hex_len);
                all_hex_data[hex_len] = '\0';
                all_hex_len = hex_len;
                PRINTF_LOG("[CLIENT][SINGLE_ENC] Tek parça ENCRYPTED:QUERY_REPLIES_ONE_REPORT yanıtı alındı, hex_len=%zu\n", hex_len);
                done = 1;
            }
        } else {
            // Başka format veya veri bekleniyor
            PRINTF_LOG("[CLIENT] Beklenen format bulunamadı, daha fazla veri bekleniyor...\n");
            continue;
        }
    }
    
    // Decrypt işlemi
    if (all_hex_data && all_hex_len > 0) {
        PRINTF_LOG("[CLIENT][DECRYPT] Hex veri decrypt ediliyor...\n");
        
        size_t encrypted_length;
        uint8_t* encrypted_bytes = hex_to_bytes(all_hex_data, &encrypted_length);
        if (!encrypted_bytes || encrypted_length < CRYPTO_IV_SIZE) {
            PRINTF_LOG("[CLIENT][DECRYPT] Hex decode hatası!\n");
            if (encrypted_bytes) free(encrypted_bytes);
            free(all_hex_data);
            return;
        }
        
        uint8_t iv[CRYPTO_IV_SIZE];
        memcpy(iv, encrypted_bytes, CRYPTO_IV_SIZE);
        
        char* decrypted_json = decrypt_data(
            encrypted_bytes + CRYPTO_IV_SIZE,
            encrypted_length - CRYPTO_IV_SIZE,
            conn->ecdh_ctx.aes_key,
            iv
        );
        
        free(encrypted_bytes);
        free(all_hex_data);
        
        if (decrypted_json) {
            PRINTF_LOG("[CLIENT][DECRYPT] Decrypt başarılı!\n");
            PRINTF_LOG("\n=== RAPORLARIMA GELEN CEVAPLAR ===\n");
            PRINTF_LOG("%s\n", decrypted_json);
            PRINTF_LOG("=====================================\n");
            free(decrypted_json);
        } else {
            PRINTF_LOG("[CLIENT][DECRYPT] Decrypt hatası!\n");
        }
    } else {
        PRINTF_LOG("[CLIENT] Hex veri alınamadı!\n");
    }
}

// Kullanıcının kendi reply'larını JWT ile sorgulayan fonksiyon
void query_my_replies_with_jwt(client_connection_t* conn, const char* jwt_token) {
    if (!conn || !jwt_token || strlen(jwt_token) == 0) {
        PRINTF_CLIENT("JWT token veya bağlantı hatalı!\n");
        return;
    }
    if (!conn->ecdh_initialized) {
        PRINTF_CLIENT("ECDH başlatılmamış - şifreli sorgu yapılamaz!\n");
        return;
    }
    
    PRINTF_LOG("[CLIENT][REPLY_QUERY] JWT ile reply sorgulama başlatılıyor...\n");
    
    // Komutu şifrele
    char cmd_json[2048];
    snprintf(cmd_json, sizeof(cmd_json), "{\"jwt\":\"%s\"}", jwt_token);
    char *protocol_message = create_encrypted_protocol_message("REPLY_QUERY", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreli sorgu mesajı oluşturulamadı!\n");
        return;
    }
    
    PRINTF_LOG("[CLIENT][REPLY_QUERY] Şifreli mesaj oluşturuldu, gönderiliyor...\n");
    
    // Mesajı socket'a direkt gönder (yanıt almayı kendimiz yapacağız)
    ssize_t bytes_sent = send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);
    if (bytes_sent < 0) {
        PRINTF_CLIENT("Şifreli sorgu gönderilemedi!\n");
        return;
    }
    PRINTF_LOG("[CLIENT][REPLY_QUERY] Mesaj gönderildi (%zd bytes), yanıt bekleniyor...\n", bytes_sent);
    
    // --- Parçalı yanıt toplama (REPLY_QUERY için) ---
    char* all_hex_data = NULL;
    size_t all_hex_len = 0;
    char* all_plain_data = NULL;
    size_t all_plain_len = 0;
    int expected_parts = 0, received_parts = 0;
    int done = 0;
    int recv_count = 0;
    char streambuf[65536];
    size_t streambuf_len = 0;
    
    while (!done) {
        PRINTF_LOG("[CLIENT][RECV] Yanıt bekleniyor...\n");
        PRINTF_LOG("[CLIENT][RECV] Toplam buffer: %zu bytes, ilk 100 karakter: %.100s\n", streambuf_len, streambuf);
        // Eğer streambuf'da yeterli veri yoksa, recv ile tamamla
        if (streambuf_len < 4096) {
            ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
            recv_count++;
            PRINTF_LOG("[CLIENT][RECV] recv_count=%d, bytes_received=%zd, buffer_len=%zu\n", recv_count, pn, streambuf_len);
            if (pn <= 0) {
                PRINTF_LOG("[CLIENT][RECV] recv hatası veya bağlantı kapatıldı: %zd\n", pn);
                break;
            }
            streambuf_len += pn;
            streambuf[streambuf_len] = '\0';
            PRINTF_LOG("[CLIENT][RECV] Toplam buffer: %zu bytes, ilk 100 karakter: %.100s\n", streambuf_len, streambuf);
        }

        PRINTF_LOG("[CLIENT][RECV] Gelen verinin ilk 100 karakteri: %.100s\n", streambuf);

        
        // ENCRYPTED:REPLY_QUERY: formatı kontrol et (tek parça encrypted)
        const char* single_encrypted_prefix = "ENCRYPTED:REPLY_QUERY:";
        if (strncmp(streambuf, single_encrypted_prefix, strlen(single_encrypted_prefix)) == 0) {
            PRINTF_LOG("[CLIENT][SINGLE_ENC] Tek parça ENCRYPTED:REPLY_QUERY yanıtı alınıyor...\n");
            const char* hex_data = streambuf + strlen(single_encrypted_prefix);
            char* newline = strchr(hex_data, '\n');
            size_t hex_len;
            
            if (newline) {
                hex_len = newline - hex_data;
            } else {
                // Newline yoksa, tüm kalan veriyi al
                hex_len = strlen(hex_data);
                // Eğer hex_len 0'dan büyükse ve son karakter \n ise, onu çıkar
                if (hex_len > 0 && hex_data[hex_len-1] == '\n') {
                    hex_len--;
                }
            }
            
            PRINTF_LOG("[CLIENT][SINGLE_ENC] Hex veri uzunluğu: %zu, newline var mı: %s\n", 
                       hex_len, newline ? "evet" : "hayır");
            
            if (hex_len > 0) {
                all_hex_data = malloc(hex_len + 1);
                memcpy(all_hex_data, hex_data, hex_len);
                all_hex_data[hex_len] = '\0';
                all_hex_len = hex_len;
                PRINTF_LOG("[CLIENT][SINGLE_ENC] Tek parça ENCRYPTED:REPLY_QUERY yanıtı alındı, hex_len=%zu\n", hex_len);
                PRINTF_LOG("[CLIENT][SINGLE_ENC] Hex data ilk 64 karakter: %.64s\n", all_hex_data);
                done = 1;
                break;
            }
        }
        
        // REPLY_QUERY: formatı kontrol et (tek parça plain)
        const char* single_plain_prefix = "REPLY_QUERY:";
        if (strncmp(streambuf, single_plain_prefix, strlen(single_plain_prefix)) == 0) {
            PRINTF_LOG("[CLIENT][REPLY_QUERY] Tek parça REPLY_QUERY yanıtı kontrol ediliyor...\n");
            const char* plain_data = streambuf + strlen(single_plain_prefix);
            const char* newline = strchr(plain_data, '\n');
            if (!newline) newline = plain_data + strlen(plain_data); // Eğer \n yoksa sonuna kadar
            size_t plain_len = newline - plain_data;
            all_plain_data = malloc(plain_len + 1);
            memcpy(all_plain_data, plain_data, plain_len);
            all_plain_data[plain_len] = '\0';
            all_plain_len = plain_len;
            PRINTF_LOG("[CLIENT][SINGLE_PLAIN] Tek parça REPLY_QUERY yanıtı alındı, plain_len=%zu\n", plain_len);
            done = 1;
            break;
        }
        
        // ENCRYPTED_PART header'ı ara (çok parçalı encrypted)
        char* encrypted_header = strstr(streambuf, "ENCRYPTED_PART:");
        if (encrypted_header) {
            PRINTF_LOG("[CLIENT][ENC_PART] Çok parçalı ENCRYPTED_PART header bulundu: %s\n", encrypted_header);
            char* after_header = encrypted_header + 15;
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
            
            // Yeterli hex verisi var mı kontrol et
            size_t available = streambuf + streambuf_len - hex_start;
            while (available < plen && recv_count < 10) {
                ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
                recv_count++;
                PRINTF_LOG("[CLIENT][RECV] hex_data tamamlanıyor, recv_count=%d, bytes=%zd\n", recv_count, pn);
                if (pn <= 0) break;
                streambuf_len += pn;
                streambuf[streambuf_len] = '\0';
                available = streambuf + streambuf_len - hex_start;
            }
            
            PRINTF_LOG("[CLIENT][ENC_PART] ENCRYPTED_PART idx=%d/%d, plen=%zu, available=%zu\n", idx, total, plen, available);
            
            all_hex_data = realloc(all_hex_data, all_hex_len + plen + 1);
            memcpy(all_hex_data + all_hex_len, hex_start, plen);
            all_hex_len += plen;
            all_hex_data[all_hex_len] = '\0';
            received_parts++;
            if (expected_parts == 0) expected_parts = total;
            
            // Tüketilen veriyi buffer'dan çıkar
            size_t consumed = (hex_start - streambuf) + plen;
            memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
            streambuf_len -= consumed;
            streambuf[streambuf_len] = '\0';
            
            if (received_parts >= expected_parts) { 
                PRINTF_LOG("[CLIENT][ENC_PART] Tüm ENCRYPTED parçalar alındı: %d/%d\n", received_parts, expected_parts);
                done = 1; 
                break; 
            }
            continue;
        }
        
        // Hiçbir format bulunamadı, çok fazla deneme yapıldı
        if (recv_count > 5) {
            PRINTF_LOG("[CLIENT][TIMEOUT] Çok fazla recv denemesi yapıldı, çıkılıyor...\n");
            break;
        }
    }
    
    PRINTF_LOG("[CLIENT][RESULT] recv_count=%d, all_hex_len=%zu, all_plain_len=%zu\n", 
               recv_count, all_hex_len, all_plain_len);
    
    // Sonuçları işle
    if (all_hex_data && all_hex_len > 16) {
        PRINTF_LOG("[CLIENT][DECRYPT] Encrypted data çözülüyor...\n");
        size_t encrypted_length;
        uint8_t* encrypted_bytes = hex_to_bytes(all_hex_data, &encrypted_length);
        if (!encrypted_bytes || encrypted_length < CRYPTO_IV_SIZE) {
            PRINTF_LOG("[CLIENT][DECRYPT] Hex decode hatası!\n");
            if (encrypted_bytes) free(encrypted_bytes);
            free(all_hex_data);
            return;
        }
        uint8_t iv[CRYPTO_IV_SIZE];
        memcpy(iv, encrypted_bytes, CRYPTO_IV_SIZE);
        char* decrypted_json = decrypt_data(
            encrypted_bytes + CRYPTO_IV_SIZE,
            encrypted_length - CRYPTO_IV_SIZE,
            conn->ecdh_ctx.aes_key,
            iv
        );
        free(encrypted_bytes);
        free(all_hex_data);
        if (decrypted_json) {
            PRINTF_CLIENT("\n[REPLY_QUERY] Şifreli cevap çözüldü:\n%s\n", decrypted_json);
            free(decrypted_json);
        } else {
            PRINTF_CLIENT("Şifreli cevap çözülemedi!\n");
        }
    } else if (all_plain_data && all_plain_len > 0) {
        PRINTF_CLIENT("\n[REPLY_QUERY] Plain cevap alındı:\n%s\n", all_plain_data);
        free(all_plain_data);
    } else {
        PRINTF_CLIENT("Reply sorgusu başarısız veya bağlantı hatası!\n");
        if (all_hex_data) free(all_hex_data);
        if (all_plain_data) free(all_plain_data);
    }
}

void query_my_replies(client_connection_t* conn, const char* jwt_token) {
    if (!conn || !jwt_token || strlen(jwt_token) == 0) {
        PRINTF_CLIENT("JWT token veya bağlantı hatalı!\n");
        return;
    }
    if (!conn->ecdh_initialized) {
        PRINTF_CLIENT("ECDH başlatılmamış - şifreli sorgu yapılamaz!\n");
        return;
    }
    
    PRINTF_LOG("[CLIENT][QUERY_MY_REPLIES] Raporlarıma gelen cevapları sorgulama başlatılıyor...\n");
    
    // JSON komutu oluştur
    char cmd_json[2048];
    snprintf(cmd_json, sizeof(cmd_json), "{\"jwt\":\"%s\"}", jwt_token);
    
    // QUERY_MY_REPLIES komutu şifrele ve gönder
    char* protocol_message = create_encrypted_protocol_message("QUERY_MY_REPLIES", cmd_json, conn->ecdh_ctx.aes_key, jwt_token);
    if (!protocol_message) {
        PRINTF_CLIENT("Şifreleme hatası!\n");
        return;
    }
    
    // Mesajı socket'a direkt gönder
    ssize_t bytes_sent = send(conn->socket, protocol_message, strlen(protocol_message), 0);
    free(protocol_message);
    if (bytes_sent < 0) {
        PRINTF_CLIENT("Şifreli sorgu gönderilemedi!\n");
        return;
    }
    
    PRINTF_LOG("QUERY_MY_REPLIES komutu gönderildi (%zd bytes), yanıt bekleniyor...\n", bytes_sent);
    
    // --- Parçalı yanıt toplama (QUERY_MY_REPLIES için) ---
    char* all_hex_data = NULL;
    size_t all_hex_len = 0;
    int expected_parts = 0, received_parts = 0;
    int done = 0;
    int recv_count = 0;
    char streambuf[65536];
    size_t streambuf_len = 0;

    while (!done) {
        PRINTF_LOG("[CLIENT][RECV] Yanıt bekleniyor...\n");
        // Eğer streambuf'da yeterli veri yoksa, recv ile tamamla
        if (streambuf_len < 4096) {
            ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
            recv_count++;
            PRINTF_LOG("[CLIENT][RECV] recv_count=%d, bytes_received=%zd, buffer_len=%zu\n", recv_count, pn, streambuf_len);
            if (pn <= 0) {
                PRINTF_LOG("[CLIENT][RECV] recv hatası veya bağlantı kapatıldı: %zd\n", pn);
                break;
            }
            streambuf_len += pn;
            streambuf[streambuf_len] = '\0';
            PRINTF_LOG("[CLIENT][RECV] Toplam buffer: %zu bytes, ilk 100 karakter: %.100s\n", streambuf_len, streambuf);
        }

        // ENCRYPTED:QUERY_MY_REPLIES: formatı kontrol et (tek parça encrypted)
        const char* single_encrypted_prefix = "ENCRYPTED:QUERY_MY_REPLIES:";
        if (strncmp(streambuf, single_encrypted_prefix, strlen(single_encrypted_prefix)) == 0) {
            PRINTF_LOG("[CLIENT][SINGLE_ENC] Tek parça ENCRYPTED:QUERY_MY_REPLIES yanıtı alınıyor...\n");
            const char* hex_data = streambuf + strlen(single_encrypted_prefix);
            char* newline = strchr(hex_data, '\n');
            size_t hex_len;
            if (newline) {
                hex_len = newline - hex_data;
            } else {
                hex_len = strlen(hex_data);
                if (hex_len > 0 && hex_data[hex_len-1] == '\n') {
                    hex_len--;
                }
            }
            PRINTF_LOG("[CLIENT][SINGLE_ENC] Hex veri uzunluğu: %zu\n", hex_len);
            if (hex_len > 0) {
                all_hex_data = malloc(hex_len + 1);
                memcpy(all_hex_data, hex_data, hex_len);
                all_hex_data[hex_len] = '\0';
                all_hex_len = hex_len;
                PRINTF_LOG("[CLIENT][SINGLE_ENC] Tek parça ENCRYPTED:QUERY_MY_REPLIES yanıtı alındı, hex_len=%zu\n", hex_len);
                done = 1;
                break;
            }
        }

        // ENCRYPTED_PART: formatı kontrol et (çok parçalı encrypted, yeni format)
        char* encrypted_header = strstr(streambuf, "ENCRYPTED_PART:");
        if (encrypted_header) {
            PRINTF_LOG("[CLIENT][ENC_PART] Çok parçalı ENCRYPTED_PART header bulundu: %s\n", encrypted_header);
            char* after_header = encrypted_header + strlen("ENCRYPTED_PART:");
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
            // Yeterli hex verisi var mı kontrol et
            size_t available = streambuf + streambuf_len - hex_start;
            while (available < plen && recv_count < 10) {
                ssize_t pn = recv(conn->socket, streambuf + streambuf_len, sizeof(streambuf) - streambuf_len - 1, 0);
                recv_count++;
                PRINTF_LOG("[CLIENT][RECV] hex_data tamamlanıyor, recv_count=%d, bytes=%zd\n", recv_count, pn);
                if (pn <= 0) break;
                streambuf_len += pn;
                streambuf[streambuf_len] = '\0';
                available = streambuf + streambuf_len - hex_start;
            }
            PRINTF_LOG("[CLIENT][ENC_PART] ENCRYPTED_PART idx=%d/%d, plen=%zu, available=%zu\n", idx, total, plen, available);
            all_hex_data = realloc(all_hex_data, all_hex_len + plen + 1);
            memcpy(all_hex_data + all_hex_len, hex_start, plen);
            all_hex_len += plen;
            all_hex_data[all_hex_len] = '\0';
            received_parts++;
            if (expected_parts == 0) expected_parts = total;
            // Tüketilen veriyi buffer'dan çıkar
            size_t consumed = (hex_start - streambuf) + plen;
            memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
            streambuf_len -= consumed;
            streambuf[streambuf_len] = '\0';
            if (received_parts >= expected_parts) {
                PRINTF_LOG("[CLIENT][ENC_PART] Tüm ENCRYPTED parçalar alındı: %d/%d\n", received_parts, expected_parts);
                done = 1;
                break;
            }
            continue;
        }

        // Hiçbir format bulunamadı, daha fazla veri bekleniyor
        PRINTF_LOG("[CLIENT] Beklenen format bulunamadı, daha fazla veri bekleniyor...\n");
        if (recv_count > 10) {
            PRINTF_LOG("[CLIENT][TIMEOUT] Çok fazla recv denemesi yapıldı, çıkılıyor...\n");
            break;
        }
    }

    // Decrypt işlemi
    if (all_hex_data && all_hex_len > 0) {
        PRINTF_LOG("[CLIENT][DECRYPT] Hex veri decrypt ediliyor...\n");
        size_t encrypted_length;
        uint8_t* encrypted_bytes = hex_to_bytes(all_hex_data, &encrypted_length);
        if (!encrypted_bytes || encrypted_length < CRYPTO_IV_SIZE) {
            PRINTF_LOG("[CLIENT][DECRYPT] Hex decode hatası!\n");
            if (encrypted_bytes) free(encrypted_bytes);
            free(all_hex_data);
            return;
        }
        uint8_t iv[CRYPTO_IV_SIZE];
        memcpy(iv, encrypted_bytes, CRYPTO_IV_SIZE);
        char* decrypted_json = decrypt_data(
            encrypted_bytes + CRYPTO_IV_SIZE,
            encrypted_length - CRYPTO_IV_SIZE,
            conn->ecdh_ctx.aes_key,
            iv
        );
        free(encrypted_bytes);
        free(all_hex_data);
        if (decrypted_json) {
            PRINTF_LOG("[CLIENT][DECRYPT] Decrypt başarılı!\n");
            PRINTF_LOG("\n=== RAPORLARIMA GELEN CEVAPLAR ===\n");
            PRINTF_LOG("%s\n", decrypted_json);
            PRINTF_LOG("=====================================\n");
            free(decrypted_json);
        } else {
            PRINTF_LOG("[CLIENT][DECRYPT] Decrypt hatası!\n");
        }
    } else {
        PRINTF_LOG("[CLIENT] Hex veri alınamadı!\n");
    }
}
