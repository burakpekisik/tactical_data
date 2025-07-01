#include "get_report_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
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

    // --- Yanıt alma (hem tek parça hem parçalı destekli) ---
    char* all_hex_data = NULL;
    size_t all_hex_len = 0;
    int expected_parts = 0, received_parts = 0;
    int done = 0;
    int recv_count = 0;
    char streambuf[131072];  // Buffer boyutunu artır
    size_t streambuf_len = 0;
    int max_attempts = 100;  // Maksimum deneme sayısı artır
    int attempts = 0;
    int no_progress_count = 0;
    int is_single_response = 0;  // Tek parça yanıt mı?
    
    while (!done && attempts < max_attempts) {
        attempts++;
        int made_progress = 0;
        
        // Yeni veri al
        if (streambuf_len < 8192 || no_progress_count > 3) {
            size_t remaining_space = sizeof(streambuf) - streambuf_len - 1;
            if (remaining_space > 1024) {
                ssize_t pn = recv(conn->socket, streambuf + streambuf_len, remaining_space, 0);
                recv_count++;
                PRINTF_LOG("[CLIENT][RECV] recv_count=%d, pn=%zd, attempt=%d\n", recv_count, pn, attempts);
                if (pn <= 0) {
                    PRINTF_LOG("[CLIENT][RECV] recv() hatası veya bağlantı kapandı\n");
                    break;
                }
                streambuf_len += pn;
                streambuf[streambuf_len] = '\0';
                no_progress_count = 0;
            }
        }
        
        // Önce tek parça ENCRYPTED yanıt kontrolü yap (farklı formatları destekler)
        char* encrypted_header = strstr(streambuf, "ENCRYPTED:");
        char* report_query_header = strstr(streambuf, "REPORT_QUERY:");
        
        if ((encrypted_header || report_query_header) && !strstr(streambuf, "ENCRYPTED_PART:")) {
            // Bu tek parça yanıt
            is_single_response = 1;
            char* data_start = NULL;
            char* header_type = NULL;
            
            if (encrypted_header) {
                data_start = encrypted_header + 10; // "ENCRYPTED:" uzunluğu
                header_type = "ENCRYPTED";
                PRINTF_LOG("[CLIENT][SINGLE] Tek parça ENCRYPTED yanıt tespit edildi\n");
            } else if (report_query_header) {
                data_start = report_query_header + 13; // "REPORT_QUERY:" uzunluğu
                header_type = "REPORT_QUERY";
                PRINTF_LOG("[CLIENT][SINGLE] Tek parça REPORT_QUERY yanıt tespit edildi\n");
            }
            
            if (data_start) {
                // Satır sonu bulana kadar veriyi al
                char* line_end = strchr(data_start, '\n');
                if (!line_end) line_end = strchr(data_start, '\0');
                
                if (line_end && line_end > data_start) {
                    size_t data_len = line_end - data_start;
                    char* full_data = malloc(data_len + 1);
                    if (full_data) {
                        memcpy(full_data, data_start, data_len);
                        full_data[data_len] = '\0';
                        
                        PRINTF_LOG("[CLIENT][SINGLE] Full data: %s\n", full_data);
                        
                        char* hex_data = NULL;
                        size_t hex_len = 0;
                        
                        // Farklı formatları dene:
                        // 1. filename:hex_data:jwt_token formatı
                        char* first_colon = strchr(full_data, ':');
                        if (first_colon) {
                            char* second_colon = strchr(first_colon + 1, ':');
                            if (second_colon) {
                                // Format: filename:hex_data:jwt_token
                                hex_data = first_colon + 1;
                                hex_len = second_colon - hex_data;
                                PRINTF_LOG("[CLIENT][SINGLE] Format: filename:hex_data:jwt_token\n");
                            } else {
                                // Format: header:hex_data veya filename:hex_data
                                hex_data = first_colon + 1;
                                hex_len = data_len - (hex_data - full_data);
                                PRINTF_LOG("[CLIENT][SINGLE] Format: header:hex_data\n");
                            }
                        } else {
                            // Format: sadece hex_data
                            hex_data = full_data;
                            hex_len = data_len;
                            PRINTF_LOG("[CLIENT][SINGLE] Format: sadece hex_data\n");
                        }
                        
                        if (hex_data && hex_len > 0) {
                            // Hex data'nın geçerli olup olmadığını kontrol et (sadece hex karakterleri)
                            int is_valid_hex = 1;
                            for (size_t i = 0; i < hex_len; i++) {
                                char c = hex_data[i];
                                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                                    is_valid_hex = 0;
                                    break;
                                }
                            }
                            
                            if (is_valid_hex && hex_len % 2 == 0) { // Hex string çift sayıda karakter olmalı
                                PRINTF_LOG("[CLIENT][SINGLE] Geçerli hex data bulundu, uzunluk: %zu\n", hex_len);
                                
                                all_hex_data = malloc(hex_len + 1);
                                if (all_hex_data) {
                                    memcpy(all_hex_data, hex_data, hex_len);
                                    all_hex_data[hex_len] = '\0';
                                    all_hex_len = hex_len;
                                    received_parts = 1;
                                    expected_parts = 1;
                                    done = 1;
                                    made_progress = 1;
                                    PRINTF_LOG("[CLIENT][SINGLE] Hex data başarıyla ayrıştırıldı: %.32s...\n", all_hex_data);
                                }
                            } else {
                                PRINTF_LOG("[CLIENT][SINGLE] Geçersiz hex data: uzunluk=%zu, is_valid_hex=%d\n", hex_len, is_valid_hex);
                            }
                        } else {
                            PRINTF_LOG("[CLIENT][SINGLE] Hex data bulunamadı\n");
                        }
                        
                        free(full_data);
                    }
                }
            }
        }
        
        // Eğer tek parça değilse, parçalı yanıt işleme
        if (!is_single_response && !done) {
            // Stream buffer'da ENCRYPTED_PART header'larını ara ve işle
            while (1) {
                char* header = strstr(streambuf, "ENCRYPTED_PART:");
                if (!header) break;
                
                char* after_header = header + 15;
                int idx = 0, total = 0;
                size_t plen = 0;
                int n = sscanf(after_header, "%d:%d:%zu:", &idx, &total, &plen);
                if (n != 3) {
                    PRINTF_LOG("[CLIENT][PARSE] ENCRYPTED_PART header parse hatası! n=%d\n", n);
                    // Bu header'ı atla ve devam et
                    size_t consumed = (after_header - streambuf) + 1;
                    if (consumed < streambuf_len) {
                        memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
                        streambuf_len -= consumed;
                        streambuf[streambuf_len] = '\0';
                    }
                    continue;
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
                    // Bu header'ı atla
                    size_t consumed = (hex_start - streambuf) + 1;
                    if (consumed < streambuf_len) {
                        memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
                        streambuf_len -= consumed;
                        streambuf[streambuf_len] = '\0';
                    }
                    continue;
                }
                
                // Şimdi hex_start'tan itibaren plen kadar hex karakteri almalıyız
                size_t available = streambuf + streambuf_len - hex_start;
                
                // Yeterli veri var mı kontrol et
                if (available < plen) {
                    PRINTF_LOG("[CLIENT][PARSE] Yeterli hex verisi yok: available=%zu, needed=%zu\n", available, plen);
                    // Daha fazla veri bekle, döngüden çık
                    break;
                }
                
                // Artık hex_data'nın tamamı buffer'da, parçayı işle
                PRINTF_LOG("[CLIENT][PARSE] ENCRYPTED_PART idx=%d/%d, plen=%zu, available=%zu, all_hex_len=%zu\n", idx, total, plen, available, all_hex_len);
                PRINTF_LOG("[CLIENT][PARSE] hex_data ilk 16: %.16s, son 16: %.16s\n", hex_start, hex_start + (plen > 16 ? plen-16 : 0));
                
                all_hex_data = realloc(all_hex_data, all_hex_len + plen + 1);
                if (!all_hex_data) {
                    PRINTF_LOG("[CLIENT][PARSE] Bellek tahsisi hatası!\n");
                    done = 1;
                    break;
                }
                
                memcpy(all_hex_data + all_hex_len, hex_start, plen);
                all_hex_len += plen;
                all_hex_data[all_hex_len] = '\0';
                received_parts++;
                made_progress = 1;
                
                if (expected_parts == 0) expected_parts = total;
                
                // Header+hex_data'nın sonrasını streambuf'a kaydır
                size_t consumed = (hex_start - streambuf) + plen;
                if (consumed <= streambuf_len) {
                    memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
                    streambuf_len -= consumed;
                    streambuf[streambuf_len] = '\0';
                } else {
                    // Buffer hatası, temizle
                    streambuf_len = 0;
                    streambuf[0] = '\0';
                }
                
                PRINTF_LOG("[CLIENT][PROGRESS] Parça %d/%d tamamlandı\n", received_parts, expected_parts);
                
                if (received_parts >= expected_parts) { 
                    done = 1; 
                    break; 
                }
            }
        }
        
        if (done) break;
        
        // İlerleme kontrolü
        if (!made_progress) {
            no_progress_count++;
            if (no_progress_count > 10) {
                usleep(50000); // 50ms bekle
            }
        } else {
            no_progress_count = 0;
        }
    }
    
    while (!done && attempts < max_attempts) {
        attempts++;
        int made_progress = 0;
        
        // Stream buffer'da ENCRYPTED_PART header'larını ara ve işle
        while (1) {
            char* header = strstr(streambuf, "ENCRYPTED_PART:");
            if (!header) break;
            
            char* after_header = header + 15;
            int idx = 0, total = 0;
            size_t plen = 0;
            int n = sscanf(after_header, "%d:%d:%zu:", &idx, &total, &plen);
            if (n != 3) {
                PRINTF_LOG("[CLIENT][PARSE] ENCRYPTED_PART header parse hatası! n=%d\n", n);
                // Bu header'ı atla ve devam et
                size_t consumed = (after_header - streambuf) + 1;
                if (consumed < streambuf_len) {
                    memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
                    streambuf_len -= consumed;
                    streambuf[streambuf_len] = '\0';
                }
                continue;
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
                // Bu header'ı atla
                size_t consumed = (hex_start - streambuf) + 1;
                if (consumed < streambuf_len) {
                    memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
                    streambuf_len -= consumed;
                    streambuf[streambuf_len] = '\0';
                }
                continue;
            }
            
            // Şimdi hex_start'tan itibaren plen kadar hex karakteri almalıyız
            size_t available = streambuf + streambuf_len - hex_start;
            
            // Yeterli veri var mı kontrol et
            if (available < plen) {
                PRINTF_LOG("[CLIENT][PARSE] Yeterli hex verisi yok: available=%zu, needed=%zu\n", available, plen);
                // Daha fazla veri bekle, döngüden çık
                break;
            }
            
            // Artık hex_data'nın tamamı buffer'da, parçayı işle
            PRINTF_LOG("[CLIENT][PARSE] ENCRYPTED_PART idx=%d/%d, plen=%zu, available=%zu, all_hex_len=%zu\n", idx, total, plen, available, all_hex_len);
            PRINTF_LOG("[CLIENT][PARSE] hex_data ilk 16: %.16s, son 16: %.16s\n", hex_start, hex_start + (plen > 16 ? plen-16 : 0));
            
            all_hex_data = realloc(all_hex_data, all_hex_len + plen + 1);
            if (!all_hex_data) {
                PRINTF_LOG("[CLIENT][PARSE] Bellek tahsisi hatası!\n");
                done = 1;
                break;
            }
            
            memcpy(all_hex_data + all_hex_len, hex_start, plen);
            all_hex_len += plen;
            all_hex_data[all_hex_len] = '\0';
            received_parts++;
            made_progress = 1;
            
            if (expected_parts == 0) expected_parts = total;
            
            // Header+hex_data'nın sonrasını streambuf'a kaydır
            size_t consumed = (hex_start - streambuf) + plen;
            if (consumed <= streambuf_len) {
                memmove(streambuf, streambuf + consumed, streambuf_len - consumed);
                streambuf_len -= consumed;
                streambuf[streambuf_len] = '\0';
            } else {
                // Buffer hatası, temizle
                streambuf_len = 0;
                streambuf[0] = '\0';
            }
            
            PRINTF_LOG("[CLIENT][PROGRESS] Parça %d/%d tamamlandı\n", received_parts, expected_parts);
            
            if (received_parts >= expected_parts) { 
                done = 1; 
                break; 
            }
        }
        
        if (done) break;
        
        // Eğer bu iterasyonda ilerleme kaydedilmediyse ve buffer'da yeterli veri yoksa, yeni veri al
        if (!made_progress) {
            no_progress_count++;
            
            // Buffer'da bekleyen veri var mı kontrol et
            if (streambuf_len < 1024 || no_progress_count > 5) {
                size_t remaining_space = sizeof(streambuf) - streambuf_len - 1;
                if (remaining_space > 1024) {  // Buffer overflow kontrolü
                    ssize_t pn = recv(conn->socket, streambuf + streambuf_len, remaining_space, 0);
                    recv_count++;
                    PRINTF_LOG("[CLIENT][RECV] recv_count=%d, pn=%zd, attempt=%d\n", recv_count, pn, attempts);
                    if (pn <= 0) {
                        PRINTF_LOG("[CLIENT][RECV] recv() hatası veya bağlantı kapandı\n");
                        break;
                    }
                    streambuf_len += pn;
                    streambuf[streambuf_len] = '\0';
                    no_progress_count = 0;  // Yeni veri aldık, sayacı sıfırla
                } else {
                    PRINTF_LOG("[CLIENT][RECV] Buffer dolu, veri işleniyor\n");
                    break;
                }
            } else {
                // Kısa bir süre bekle
                usleep(10000); // 10ms bekle
            }
        } else {
            no_progress_count = 0;  // İlerleme oldu, sayacı sıfırla
        }
    }
    // Son kontrol - timeout kontrolü
    if (!done && attempts >= max_attempts) {
        PRINTF_LOG("[CLIENT][TIMEOUT] Maksimum deneme sayısına ulaşıldı, timeout!\n");
        PRINTF_LOG("[CLIENT][STATUS] Alınan parça sayısı: %d/%d\n", received_parts, expected_parts);
        
        // Kısmi sonuç bile varsa onu işlemeye çalış
        if (received_parts > 0 && all_hex_data && all_hex_len > 16) {
            PRINTF_LOG("[CLIENT][PARTIAL] Kısmi sonuçla devam etmeye çalışılıyor...\n");
        } else {
            if (all_hex_data) free(all_hex_data);
            return -1;
        }
    }
    
    PRINTF_LOG("[CLIENT][RECV] Tüm parçalar alındı. received_parts=%d, expected_parts=%d, toplam_len=%zu\n", received_parts, expected_parts, all_hex_len);
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