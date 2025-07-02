#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <jwt.h>
#include <cjson/cJSON.h>
#include <pthread.h>
#include "config.h"
#include "logger.h"
#include "jwt_manager.h"
#include "crypto_utils.h"
#include "database.h"
#include "json_utils.h"
#include "encrypted_server.h"
#include "report_query_handler.h"
#include "admin_notify_manager.h"
#include "admin_reply_manager.h"
#include "thread_monitor.h"
#include "large_response.h"
#include "protocol_parser.h"
#include "connection_manager.h"

// Forward declarations
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token, int client_socket, const char* client_ip, int client_port);

/// @brief Sunucu çalışma durumu için global flag - signal handling için
static volatile sig_atomic_t server_running = 1;

/**
 * @brief Graceful shutdown için signal handler
 * @ingroup server
 * 
 * SIGTERM ve SIGINT sinyallerini yakalayarak sunucunun temiz bir şekilde
 * kapatılmasını sağlar. Tüm bağlantıları kapatır ve kaynakları temizler.
 * 
 * Temizlik sırası:
 * 1. TCP sunucusunu durdurur
 * 2. Veritabanı bağlantısını kapatır
 * 3. Konsol mesajı yazdırır
 * 4. Program çıkışı yapar
 * 
 * @param sig Yakalanan sinyal numarası (SIGTERM=15, SIGINT=2)
 * 
 * @note Bu fonksiyon async-signal-safe'dir ve signal context'inde güvenli çalışır
 * @warning exit() çağrısı yapar, program anında sonlanır
 * 
 * @see stop_tcp_server()
 * @see db_close()
 */
// Signal handler for graceful shutdown
void handle_signal(int sig) {
    LOG_SERVER_INFO("Signal %d received, shutting down server...", sig);
    PRINTF_SERVER("\n🛑 Signal %d alındı, server kapatılıyor...\n", sig);
    server_running = 0;
    
    // TCP server'ı durdur
    LOG_SERVER_INFO("Stopping TCP server...");
    stop_tcp_server();
    
    // Database'i kapat
    LOG_SERVER_INFO("Closing database connection...");
    db_close();
    
    // Logger'ı temizle
    logger_cleanup(LOGGER_SERVER);
    
    PRINTF_LOG("✓ Server temiz bir şekilde kapatıldı\n");
    exit(0);
}

/**
 * @brief Şifreli JSON isteklerini işler ve veritabanına kaydeder
 * @ingroup server
 * 
 * Bu fonksiyon ENCRYPTED protokol komutunu işler. Hex formatındaki
 * şifreli veriyi çözer, JSON'a dönüştürür ve veritabanına kaydeder.
 * 
 * İşlem adımları:
 * 1. Session key geçerliliğini kontrol eder
 * 2. Hex string'i byte array'e çevirir
 * 3. İlk 16 byte'ı IV olarak ayırır
 * 4. AES256 ile veriyi decrypt eder
 * 5. Decrypted JSON'u tactical data'ya parse eder
 * 6. Veritabanına kaydeder ve response üretir
 * 7. Tüm belleği temizler
 * 
 * @param filename İşlem yapılacak dosya adı (log için)
 * @param encrypted_content Hex formatında şifreli veri
 * @param session_key ECDH ile üretilen AES256 session key
 * 
 * @return Başarıda parse sonucu string'i (malloc'lu)
 * @return Hata durumunda hata mesajı (malloc'lu)
 * 
 * @note Döndürülen string caller tarafından free edilmelidir.
 *       Fonksiyon tüm geçici belleği otomatik temizler.
 * 
 * @warning Session key NULL olmamalı, aksi halde hata döner.
 *          Encrypted data en az IV boyutu (16 byte) içermelidir.
 * 
 * Hata durumları:
 * - NULL session key
 * - Geçersiz hex format
 * - Yetersiz veri boyutu (IV eksik)
 * - Decryption başarısızlığı
 * - JSON parse hatası
 * 
 * @see hex_to_bytes()
 * @see decrypt_data()
 * @see parse_json_to_tactical_data()
 * @see db_save_tactical_data_and_get_response()
 */
// Sifreli istek ile bas et
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token, int client_socket, const char* client_ip, int client_port) {
    PRINTF_LOG("[DEBUG] handle_encrypted_request: filename=%s, client_socket=%d, client_ip=%s, client_port=%d, jwt_token=%s\n", filename, client_socket, client_ip ? client_ip : "(null)", client_port, jwt_token ? jwt_token : "(null)");
    if (session_key == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Session key NULL");
        return error_msg;
    }
    size_t encrypted_length;
    uint8_t* encrypted_bytes = hex_to_bytes(encrypted_content, &encrypted_length);
    if (encrypted_bytes == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Gecersiz hex format");
        return error_msg;
    }
    if (encrypted_length < CRYPTO_IV_SIZE) {
        free(encrypted_bytes);
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Yetersiz veri boyutu (IV eksik)");
        return error_msg;
    }
    uint8_t iv[CRYPTO_IV_SIZE];
    memcpy(iv, encrypted_bytes, CRYPTO_IV_SIZE);
    char* decrypted_json = decrypt_data(
        encrypted_bytes + CRYPTO_IV_SIZE,
        encrypted_length - CRYPTO_IV_SIZE,
        session_key,
        iv
    );
    free(encrypted_bytes);
    if (decrypted_json == NULL) {
        char *error_msg = malloc(256);
        strcpy(error_msg, "HATA: Decryption basarisiz");
        return error_msg;
    }
    PRINTF_LOG("[DEBUG] Decrypted JSON: %s\n", decrypted_json);
    // Eğer dosya adı REPORT_QUERY, REPLY_QUERY veya QUERY_MY_REPLIES ise, rapor sorgulama işlemi yap
    if (strcmp(filename, "REPORT_QUERY") == 0 || strcmp(filename, "REPLY_QUERY") == 0 || strcmp(filename, "QUERY_MY_REPLIES") == 0 || strcmp(filename, "QUERY_REPLIES_ONE_REPORT") == 0) {
        cJSON* root = cJSON_Parse(decrypted_json);
        char* jwt_from_json = NULL;
        if (root) {
            cJSON* jwt_item = cJSON_GetObjectItem(root, "jwt");
            if (jwt_item && cJSON_IsString(jwt_item)) {
                jwt_from_json = jwt_item->valuestring;
            }
        }
        char* plain_result = malloc(65536);
        if (strcmp(filename, "REPORT_QUERY") == 0) {
            if (jwt_from_json) {
                handle_report_query(jwt_from_json, plain_result, 65536);
                PRINTF_LOG("[SERVER][ENCRYPTED] REPORT_QUERY işlendi, yanıt uzunluğu: %zu\n", strlen(plain_result));
            } else {
                snprintf(plain_result, 65536, "{\"error\":\"JWT bulunamadı\"}");
            }
        } else if (strcmp(filename, "REPLY_QUERY") == 0) {
            if (jwt_from_json) {
                handle_reply_query(jwt_from_json, plain_result, 65536);
                PRINTF_LOG("[SERVER][ENCRYPTED] REPLY_QUERY işlendi, yanıt uzunluğu: %zu\n", strlen(plain_result));
            } else {
                snprintf(plain_result, 65536, "{\"error\":\"JWT bulunamadı\"}");
            }
        } else if (strcmp(filename, "QUERY_MY_REPLIES") == 0) {
            if (jwt_from_json) {
                handle_query_my_replies(jwt_from_json, plain_result, 65536);
                PRINTF_LOG("[SERVER][ENCRYPTED] QUERY_MY_REPLIES işlendi, yanıt uzunluğu: %zu\n", strlen(plain_result));
            } else {
                snprintf(plain_result, 65536, "{\"error\":\"JWT bulunamadı\"}");
            }
        } else if (strcmp(filename, "QUERY_REPLIES_ONE_REPORT") == 0) {
            if (jwt_from_json) {
                int report_id_from_json = -1;

                cJSON* report_id = cJSON_GetObjectItem(root, "report_id");
                if (report_id && cJSON_IsNumber(report_id)) {
                    report_id_from_json = report_id->valueint;
                } else if (report_id && cJSON_IsString(report_id)) {
                    report_id_from_json = atoi(report_id->valuestring);
                }

                if (report_id_from_json <= 0) {
                    snprintf(plain_result, 65536, "{\"error\":\"report_id bulunamadı veya geçersiz\"}");
                } else {
                    handle_query_replies_to_one_report(jwt_from_json, plain_result, 65536, report_id_from_json);
                    PRINTF_LOG("[SERVER][ENCRYPTED] QUERY_REPLIES_ONE_REPORT işlendi, report_id=%d, yanıt uzunluğu: %zu\n", report_id_from_json, strlen(plain_result));
                }
            } else {
                snprintf(plain_result, 65536, "{\"error\":\"JWT bulunamadı\"}");
            }
        } else {
            snprintf(plain_result, 65536, "{\"error\":\"Geçersiz işlem adı\"}");
        }
        if (root) cJSON_Delete(root);
        uint8_t iv[CRYPTO_IV_SIZE];
        generate_random_iv(iv);
        crypto_result_t* encrypted = encrypt_data(plain_result, session_key, iv);
        free(plain_result);
        if (!encrypted || !encrypted->success) {
            if (encrypted) free_crypto_result(encrypted);
            free(decrypted_json);
            char* error_msg = malloc(256);
            strcpy(error_msg, "HATA: Yanıt şifrelenemedi");
            return error_msg;
        }
        size_t combined_length = CRYPTO_IV_SIZE + encrypted->length;
        uint8_t* combined_data = malloc(combined_length);
        memcpy(combined_data, iv, CRYPTO_IV_SIZE);
        memcpy(combined_data + CRYPTO_IV_SIZE, encrypted->data, encrypted->length);
        char* hex_data = bytes_to_hex(combined_data, combined_length);
        free(combined_data);
        free_crypto_result(encrypted);
        size_t total_size = strlen("ENCRYPTED:") + strlen(filename) + 1 + strlen(hex_data) + 1;
        if (strlen(hex_data) > ENCRYPTED_PART_SIZE) {
            PRINTF_LOG("[SERVER] ENCRYPTED yanıtı uzun, parça parça gönderilecek. Toplam uzunluk: %zu\n", strlen(hex_data));
            if (client_socket >= 0) {
                send_large_encrypted_response(client_socket, hex_data);
            } else {
                PRINTF_LOG("[SERVER] UDP/P2P için ENCRYPTED yanıtı parça parça gönderilmiyor (client_socket yok)\n");
            }
            free(hex_data);
            free(decrypted_json);
            return NULL;
        } else {
            PRINTF_LOG("[SERVER] ENCRYPTED yanıtı kısa, tek parça gönderilecek. Uzunluk: %zu\n", strlen(hex_data));
            char* result = malloc(total_size);
            snprintf(result, total_size, "ENCRYPTED:%s:%s", filename, hex_data);
            free(hex_data);
            free(decrypted_json);
            return result;
        }
    } else if (strcmp(filename, "REPLY_REPORT") == 0) {
        // Admin reply işlemi - json_utils.c'deki parse_admin_reply_json kullan
        PRINTF_LOG("[DEBUG] REPLY_REPORT işlemi başlatılıyor\n");
        admin_reply_t* reply_data = parse_admin_reply_json(decrypted_json);
        
        if (reply_data != NULL && reply_data->is_valid) {
            PRINTF_LOG("[DEBUG] Admin reply parse edildi: report_id=%d, msg=%s\n", reply_data->report_id, reply_data->msg);
            
            // Admin'in user_id'sini JWT'den al
            int admin_user_id = -1;
            if (jwt_token) {
                jwt_t *jwt_ptr = NULL;
                if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                    const char* sub = jwt_get_grant(jwt_ptr, "sub");
                    if (sub) admin_user_id = atoi(sub);
                    jwt_free(jwt_ptr);
                }
            }
            
            if (admin_user_id <= 0) {
                char* error_msg = malloc(256);
                strcpy(error_msg, "HATA: Admin kullanıcı kimliği belirlenemedi");
                free(reply_data);
                free(decrypted_json);
                return error_msg;
            }
            
            // admin_reply_t'yi reply_t'ye dönüştür
            reply_t db_reply;
            db_reply.user_id = admin_user_id;  // ÖNEMLİ: Admin'in user_id'si kullanılıyor
            db_reply.report_id = reply_data->report_id;
            strncpy(db_reply.message, reply_data->msg, sizeof(db_reply.message) - 1);
            db_reply.message[sizeof(db_reply.message) - 1] = '\0';
            db_reply.timestamp = time(NULL);
            
            // Veritabanına kaydet
            int insert_result = db_insert_reply(&db_reply);
            
            // Reply sahibine bildirim gönder (admin_reply_manager kullanarak)
            bool notification_sent = admin_reply_manager_send_reply(reply_data->report_id, reply_data->msg, client_socket);
            
            char* current_time = get_current_time();
            char* result = malloc(1024);  // Buffer boyutunu artır
            if (insert_result > 0) {  // row ID döndürüldü - başarılı
                snprintf(result, 1024, 
                    "Admin Reply Processing Result\n"
                    "============================\n"
                    "File: %s\n"
                    "Processing Time: %s\n"
                    "Reply Saved to Database:\n"
                    "-----------------------\n"
                    "Admin User ID: %d\n"
                    "Report ID: %d\n"
                    "Message: %s\n"
                    "Timestamp: %ld\n"
                    "\n"
                    "✓ Database Operation: SUCCESS\n"
                    "✓ Reply ID: %d\n"
                    "✓ Reply successfully stored\n"
                    "✓ Notification sent: %s\n"
                    "============================",
                    filename,
                    current_time,
                    admin_user_id,
                    reply_data->report_id,
                    reply_data->msg,
                    db_reply.timestamp,
                    insert_result,
                    notification_sent ? "YES" : "NO (user offline)"
                );
            } else {  // -1 döndürüldü - hata
                snprintf(result, 512, 
                    "HATA: Admin reply veritabanına kaydedilemedi (Hata kodu: %d)", 
                    insert_result
                );
            }
            free(current_time);
            
            free(reply_data);
            free(decrypted_json);
            return result;
        } else {
            char* error_msg = malloc(256);
            strcpy(error_msg, "HATA: Admin reply verisi geçersiz format");
            if (reply_data) free(reply_data);
            free(decrypted_json);
            return error_msg;
        }
    } else {
        char* user_id_from_jwt = NULL;
        if (jwt_token) {
            jwt_t *jwt_ptr = NULL;
            int decode_result = jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
            PRINTF_LOG("[DEBUG] jwt_decode sonucu: %d\n", decode_result);
            if (decode_result == 0 && jwt_ptr) {
                const char* sub = jwt_get_grant(jwt_ptr, "sub");
                PRINTF_LOG("[DEBUG] JWT sub: %s\n", sub ? sub : "(null)");
                if (sub) user_id_from_jwt = strdup(sub);
                jwt_free(jwt_ptr);
            }
        }
        PRINTF_LOG("Decrypted JSON: %s\n", decrypted_json);
        tactical_data_t* tactical_data = parse_json_to_tactical_data(decrypted_json, filename, user_id_from_jwt);
        PRINTF_LOG("[DEBUG] tactical_data: report_id=%d, user_id=%s, is_valid=%d\n", tactical_data ? tactical_data->report_id : -1, tactical_data && tactical_data->user_id ? tactical_data->user_id : "(null)", tactical_data ? tactical_data->is_valid : -1);
        char* result;
        if (user_id_from_jwt) free(user_id_from_jwt);
        if (tactical_data != NULL && tactical_data->is_valid) {
            result = db_save_tactical_data_and_get_response(tactical_data, filename);
            cJSON* report_json_obj = parse_tactical_data_to_json(tactical_data);
            char* report_json = cJSON_Print(report_json_obj);
            int sender_privilege = 0;
            if (jwt_token) {
                jwt_t *jwt_ptr = NULL;
                if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                    sender_privilege = jwt_get_grant_int(jwt_ptr, "privilege");
                    jwt_free(jwt_ptr);
                }
            }
            if (client_socket >= 0) {
                admin_notify_manager_notify_admins(report_json, client_socket, sender_privilege);
            } else {
                // UDP/P2P için admin bildirimi burada yapılabilir
                PRINTF_LOG("[ADMIN_NOTIFY] UDP/P2P için admin bildirimi: ip=%s, port=%d\n", client_ip ? client_ip : "(null)", client_port);
            }
            cJSON_Delete(report_json_obj);
            free(report_json);
            free_tactical_data(tactical_data);
        } else {
            result = malloc(256);
            strcpy(result, "HATA: Decrypted JSON tactical data formatına uygun değil");
            if (tactical_data) free_tactical_data(tactical_data);
        }
        free(decrypted_json);
        return result;
    }
}

/**
 * @brief Client bağlantısını yöneten thread fonksiyonu
 * @ingroup server
 * 
 * Her client bağlantısı için ayrı bir thread'de çalışan ana işleyici fonksiyonu.
 * ECDH anahtar değişimi, AES şifreleme ve JSON veri işleme süreçlerini yönetir.
 * 
 * İşlem adımları:
 * 1. ECDH connection manager'ı başlatır
 * 2. Client ile anahtar değişimi yapar
 * 3. AES256 session key'i oluşturur
 * 4. Client mesajlarını dinler ve işler
 * 5. Protokol mesajlarını parse eder
 * 6. PARSE/ENCRYPTED komutlarını yürütür
 * 7. Sonuçları client'a gönderir
 * 8. Bağlantı sonunda temizlik yapar
 * 
 * Desteklenen komutlar:
 * - PARSE:filename:json_data - Normal JSON parse
 * - ENCRYPTED:filename:hex_data - Şifreli JSON parse
 * 
 * Özel durumlar:
 * - Docker health check tespiti (kısa mesajlar)
 * - Boş bağlantılar (0 byte)
 * - Protocol format hataları
 * 
 * @param arg Client socket file descriptor (int* olarak cast edilmiş)
 * 
 * @return NULL (pthread için void* dönüş)
 * 
 * @note Fonksiyon thread-safe'dir ve her client için ayrı çalışır.
 *       Bellek yönetimi tam otomatik, ECDH cleanup dahil.
 * 
 * @warning arg parametresi malloc'lu memory, fonksiyon içinde free edilir.
 *          Thread sonunda slot'u serbest bırakır.
 * 
 * @see init_ecdh_for_connection()
 * @see exchange_keys_with_peer()
 * @see parse_protocol_message()
 * @see handle_encrypted_request()
 * @see remove_thread_info()
 */
// Client ile iletisimi yonet
void* handle_client(void* arg) {
    int client_socket = *(int*)arg;
    pthread_t current_thread = pthread_self();
    free(arg); // malloc'ed memory'yi temizle

    PRINTF_LOG("Client thread baslatildi (Thread ID: %lu, Socket: %d)\n", 
           current_thread, client_socket);
    fflush(stdout);

    char buffer[CONFIG_BUFFER_SIZE];
    // İlk mesajı oku
    ssize_t bytes_received = read(client_socket, buffer, CONFIG_BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    buffer[bytes_received] = '\0';

    // Client IP'sini al
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN] = "unknown";
    if (getpeername(client_socket, (struct sockaddr*)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
    }
    PRINTF_LOG("[JWT] Client IP: %s\n", client_ip);

    // LOGIN isteği mi?
    if (strncmp(buffer, "LOGIN:", 6) == 0) {
        char username[128] = "", password[128] = "";
        sscanf(buffer + 6, "%127[^:]:%127s", username, password);
        char* jwt = login_user_with_argon2(username, password);
        if (jwt) {
            char response[2048];
            snprintf(response, sizeof(response), "JWT:%s", jwt);
            send(client_socket, response, strlen(response), 0);
            // JWT'den privilege ve user_id çek
            int privilege = 0;
            int user_id = -1;
            jwt_t *jwt_ptr = NULL;
            if (jwt_decode(&jwt_ptr, jwt, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                privilege = jwt_get_grant_int(jwt_ptr, "privilege");
                const char* sub = jwt_get_grant(jwt_ptr, "sub");
                if (sub) user_id = atoi(sub);
                jwt_free(jwt_ptr);
            }
            admin_notify_manager_add_client(client_socket, privilege, username);
            if (user_id > 0) {
                admin_reply_manager_register_user(user_id, client_socket);
            }
            free(jwt);
        } else {
            char* fail = "FAIL";
            send(client_socket, fail, strlen(fail), 0);
        }
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    
    // ECDH için anahtar değişimi yap
    connection_manager_t client_manager;
    memset(&client_manager, 0, sizeof(connection_manager_t));
    snprintf(client_manager.name, sizeof(client_manager.name), "Client-%d", client_socket);
    
    if (!init_ecdh_for_connection(&client_manager)) {
        PRINTF_LOG("ECDH başlatılamadı (Thread: %lu)\n", current_thread);
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    
    // Anahtar değişimi yap
    PRINTF_LOG("Client public key bekleniyor...\n");
    uint8_t client_public_key[ECC_PUB_KEY_SIZE];
    ssize_t received = 0;
    if (bytes_received > 0) {
        size_t to_copy = (bytes_received > ECC_PUB_KEY_SIZE) ? ECC_PUB_KEY_SIZE : bytes_received;
        memcpy(client_public_key, buffer, to_copy);
        received = to_copy;
        while (received < ECC_PUB_KEY_SIZE) {
            ssize_t r = recv(client_socket, client_public_key + received, ECC_PUB_KEY_SIZE - received, 0);
            if (r <= 0) break;
            received += r;
        }
    } else {
        received = recv(client_socket, client_public_key, ECC_PUB_KEY_SIZE, 0);
    }
    PRINTF_LOG("Client public key alındı, received=%zd\n", received);
    if (received != ECC_PUB_KEY_SIZE) {
        perror("Server public key recv hatası");
        PRINTF_LOG("Client public key alınamadı, received=%zd\n", received);
        cleanup_ecdh_for_connection(&client_manager);
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    PRINTF_LOG("Server public key gönderiliyor...\n");
    ssize_t sent = send(client_socket, client_manager.ecdh_ctx.public_key, ECC_PUB_KEY_SIZE, 0);
    PRINTF_LOG("Server public key gönderildi, sent=%zd\n", sent);
    if (sent != ECC_PUB_KEY_SIZE) {
        PRINTF_LOG("Public key gönderilemedi (Thread: %lu)\n", current_thread);
        cleanup_ecdh_for_connection(&client_manager);
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    // Shared secret hesapla
    if (!ecdh_compute_shared_secret(&client_manager.ecdh_ctx, client_public_key)) {
        PRINTF_LOG("Shared secret hesaplanamadı (Thread: %lu)\n", current_thread);
        cleanup_ecdh_for_connection(&client_manager);
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    // AES anahtarını türet
    if (!ecdh_derive_aes_key(&client_manager.ecdh_ctx)) {
        PRINTF_LOG("AES anahtarı türetilemedi (Thread: %lu)\n", current_thread);
        cleanup_ecdh_for_connection(&client_manager);
        close(client_socket);
        remove_thread_info(current_thread);
        return NULL;
    }
    PRINTF_LOG("✓ ECDH anahtar değişimi tamamlandı (Thread: %lu)\n", current_thread);
    PRINTF_LOG("✓ AES256 oturum anahtarı hazır\n", current_thread);

    // --- Bağlantı başında JWT token ile mapping güncelle (ilk mesajdan JWT ayıkla) ---
    // İlk mesajda JWT token varsa, user_id <-> socket mapping'i güncelle
    char* jwt_token_init = NULL;
    // ENCRYPTED veya PARSE mesajı ise JWT token olabilir
    if (strncmp(buffer, "ENCRYPTED:", 10) == 0) {
        char *command = NULL, *filename = NULL, *hex_data = NULL;
        if (parse_encrypted_protocol_message(buffer, &command, &filename, &hex_data, &jwt_token_init) == 0 && jwt_token_init) {
            jwt_t *jwt_ptr = NULL;
            if (jwt_decode(&jwt_ptr, jwt_token_init, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                const char* sub = jwt_get_grant(jwt_ptr, "sub");
                if (sub) {
                    int user_id = atoi(sub);
                    admin_reply_manager_register_user(user_id, client_socket);
                    PRINTF_LOG("[ADMIN_REPLY] Bağlantı başında mapping güncellendi: user_id=%d, socket=%d\n", user_id, client_socket);
                }
                jwt_free(jwt_ptr);
            }
        }
    } else if (strncmp(buffer, "PARSE:", 6) == 0) {
        // PARSE mesajında JWT token son parametre olabilir
        char *last_colon = strrchr(buffer, ':');
        if (last_colon && strlen(last_colon + 1) > 10) {
            jwt_token_init = last_colon + 1;
            jwt_t *jwt_ptr = NULL;
            if (jwt_decode(&jwt_ptr, jwt_token_init, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                const char* sub = jwt_get_grant(jwt_ptr, "sub");
                if (sub) {
                    int user_id = atoi(sub);
                    admin_reply_manager_register_user(user_id, client_socket);
                    PRINTF_LOG("[ADMIN_REPLY] Bağlantı başında mapping güncellendi: user_id=%d, socket=%d\n", user_id, client_socket);
                }
                jwt_free(jwt_ptr);
            }
        }
    }
    int request_count = 0;
    
    while (1) {
        memset(buffer, 0, CONFIG_BUFFER_SIZE);
        ssize_t bytes_received = read(client_socket, buffer, CONFIG_BUFFER_SIZE - 1);
        PRINTF_LOG("[DEBUG] handle_client döngüsü: thread_id=%lu, client_socket=%d, bytes_received=%zd\n", current_thread, client_socket, bytes_received);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                PRINTF_LOG("Client normal olarak ayrıldı (Thread: %lu)\n", current_thread);
            } else {
                PRINTF_LOG("Client bağlantı hatası (Thread: %lu, Hata: %s)\n", current_thread, strerror(errno));
            }
            // --- Bağlantı kopunca mapping'i sil ---
            admin_reply_manager_remove_user(client_socket);
            break;
        }
        request_count++;
        PRINTF_LOG("İstek alındı (Thread: %lu, İstek #%d, Boyut: %zd bytes)\n", 
               current_thread, request_count, bytes_received);
        buffer[bytes_received] = '\0';
        PRINTF_LOG("[DEBUG] handle_client: gelen mesaj: %s\n", buffer);

        // --- ADMIN_NOTIFY_LISTEN komutu parse'dan önce kontrol edilmeli ---
        char* bufptr = buffer;
        while (*bufptr == '\n' || *bufptr == ' ' || *bufptr == '\t') bufptr++;
        // --- HELLO:{jwt_token} komutu ---
        if (strncmp(bufptr, "HELLO:", 6) == 0) {
            char* jwt_token = bufptr + 6;
            jwt_t *jwt_ptr = NULL;
            if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                const char* sub = jwt_get_grant(jwt_ptr, "sub");
                if (sub) {
                    int user_id = atoi(sub);
                    admin_reply_manager_register_user(user_id, client_socket);
                    PRINTF_LOG("[ADMIN_REPLY] HELLO ile mapping güncellendi: user_id=%d, socket=%d\n", user_id, client_socket);
                }
                jwt_free(jwt_ptr);
            }
            continue;
        }
        size_t buflen = strlen(bufptr);
        while (buflen > 0 && (bufptr[buflen-1] == '\n' || bufptr[buflen-1] == ' ' || bufptr[buflen-1] == '\t')) {
            bufptr[buflen-1] = '\0';
            buflen--;
        }
        if (strncmp(bufptr, "ADMIN_NOTIFY_LISTEN:", 20) == 0) {
            char* jwt_token = bufptr + 20;
            int privilege = 0;
            char username[128] = "";
            jwt_t *jwt_ptr = NULL;
            if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                privilege = jwt_get_grant_int(jwt_ptr, "privilege");
                const char* sub = jwt_get_grant(jwt_ptr, "sub");
                if (sub) strncpy(username, sub, sizeof(username)-1);
                jwt_free(jwt_ptr);
            }
            admin_notify_manager_add_client(client_socket, privilege, username);
            PRINTF_LOG("[ADMIN_NOTIFY] ADMIN_NOTIFY_LISTEN komutu alındı, socket %d admin olarak kaydedildi (privilege=%d, username=%s)\n", client_socket, privilege, username);
            // Admin dinleme modunda sonsuz döngüde bekle
            while (1) {
                ssize_t n = recv(client_socket, buffer, sizeof(buffer)-1, 0);
                if (n <= 0) break;
                // Admin dinleme modunda başka veri beklenmiyor, sadece bağlantı açık tutuluyor
            }
            close(client_socket);
            admin_notify_manager_remove_client(client_socket);
            PRINTF_LOG("[ADMIN_NOTIFY] Admin dinleme bağlantısı kapatıldı (socket %d)\n", client_socket);
            remove_thread_info(current_thread);
            return NULL;
        }
        // --- ADMIN_NOTIFY_LISTEN sonu ---
        
        // --- ADMIN REPLY_REPORT komutu ---
        if (strncmp(bufptr, "REPLY_REPORT:", 13) == 0) {
            // Format: REPLY_REPORT:<report_id>:<message>:<jwt_token>
            char* p = bufptr + 13;
            char* msg = strchr(p, ':');
            if (!msg) msg = "";
            else {
                *msg = '\0';
                msg++;
            }
            int report_id = atoi(p);
            char* jwt_token = NULL;
            char* msg_end = strchr(msg, ':');
            if (msg_end) {
                *msg_end = '\0';
                jwt_token = msg_end + 1;
            }
            // JWT token varsa mapping güncelle
            if (jwt_token && strlen(jwt_token) > 10) {
                jwt_t *jwt_ptr = NULL;
                if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                    const char* sub = jwt_get_grant(jwt_ptr, "sub");
                    if (sub) {
                        int user_id = atoi(sub);
                        admin_reply_manager_register_user(user_id, client_socket);
                        PRINTF_LOG("[ADMIN_REPLY] REPLY_REPORT ile mapping güncellendi: user_id=%d, socket=%d\n", user_id, client_socket);
                    }
                    jwt_free(jwt_ptr);
                }
            }
            admin_reply_manager_send_reply(report_id, msg, client_socket);
            continue;
        }
        // --- ADMIN REPLY_REPORT sonu ---
        
        char *current_time = get_current_time();
        PRINTF_LOG("[%s] Mesaj alindi (%zd byte)\n", current_time, bytes_received);
        fflush(stdout);
        free(current_time);
        
        // Protokol mesajini parse et
        char *command = NULL;
        char *filename = NULL;
        char *content = NULL;
        char *jwt_token = NULL;
        int is_encrypted = 0;
        // ENCRYPTED mesajı için özel parse
        if (strncmp(buffer, "ENCRYPTED:", 10) == 0) {
            if (parse_encrypted_protocol_message(buffer, &command, &filename, &content, &jwt_token) != 0) {
                char *error_response = "HATA: Gecersiz ENCRYPTED protokol formati. Format: ENCRYPTED:FILENAME:HEXDATA:JWT";
                send(client_socket, error_response, strlen(error_response), 0);
                continue;
            }
            is_encrypted = 1;
        } else {
            if (parse_protocol_message(buffer, &command, &filename, &content) != 0) {
                // Standart parse başarısızsa REPLY_QUERY:<jwt_token> gibi iki parçalı komutları kontrol et
                char* colon = strchr(buffer, ':');
                if (colon && strncmp(buffer, "REPLY_QUERY", 11) == 0) {
                    size_t cmd_len = colon - buffer;
                    command = malloc(cmd_len + 1);
                    strncpy(command, buffer, cmd_len);
                    command[cmd_len] = '\0';
                    filename = NULL;
                    content = strdup(colon + 1);
                } else {
                    char *error_response = "HATA: Gecersiz protokol formati. Format: COMMAND:FILENAME:CONTENT";
                    send(client_socket, error_response, strlen(error_response), 0);
                    continue;
                }
            }
        }
        // --- ECDH bağlantısı için user_id <-> socket mapping güncelle ---
        if (jwt_token) {
            jwt_t *jwt_ptr = NULL;
            if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                const char* sub = jwt_get_grant(jwt_ptr, "sub");
                if (sub) {
                    int user_id = atoi(sub);
                    admin_reply_manager_register_user(user_id, client_socket);
                    PRINTF_LOG("[ADMIN_REPLY] ECDH bağlantısı için mapping güncellendi: user_id=%d, socket=%d\n", user_id, client_socket);
                }
                jwt_free(jwt_ptr);
            }
        }
        PRINTF_LOG("Komut: %s\n", command);
        PRINTF_LOG("Dosya: %s\n", filename);
        fflush(stdout);
        char *parsed_result = NULL;
        if (strcmp(command, "PARSE") == 0) {
            PRINTF_LOG("Normal JSON parse ediliyor (Tactical Data format)...\n");
            fflush(stdout);
            // JWT token'ı content'in son parametre olarak ayır
            char* json_part = NULL;
            char* jwt_token_part = NULL;
            char* last_colon = strrchr(content, ':');
            if (last_colon && strlen(last_colon + 1) > 10) // JWT token uzunluğu kontrolü
            {
                size_t json_len = last_colon - content;
                json_part = malloc(json_len + 1);
                strncpy(json_part, content, json_len);
                json_part[json_len] = '\0';
                jwt_token_part = strdup(last_colon + 1);
            } else {
                json_part = strdup(content);
                jwt_token_part = NULL;
            }
            char* user_id_from_jwt = NULL;
            if (!jwt_token_part) {
                PRINTF_LOG("HATA: PARSE mesajında JWT token yok!\n");
                char* error_response = "HATA: PARSE mesajında JWT token yok!";
                send(client_socket, error_response, strlen(error_response), 0);
                free(json_part);
                continue;
            }
            PRINTF_LOG("[DEBUG] Gelen JWT token: %s\n", jwt_token_part);
            int verify_result = verify_jwt(jwt_token_part);
            PRINTF_LOG("[DEBUG] verify_jwt sonucu: %d\n", verify_result);
            jwt_t *jwt_ptr = NULL;
            int decode_result = -1;
            decode_result = jwt_decode(&jwt_ptr, jwt_token_part, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
            PRINTF_LOG("[DEBUG] jwt_decode sonucu: %d\n", decode_result);
            if (decode_result == 0 && jwt_ptr) {
                const char* sub = jwt_get_grant(jwt_ptr, "sub");
                PRINTF_LOG("[DEBUG] JWT sub: %s\n", sub ? sub : "(null)");
                if (sub) user_id_from_jwt = strdup(sub);
                jwt_free(jwt_ptr);
            }
            // JSON'u tactical data struct'ına parse et
            tactical_data_t* tactical_data = parse_json_to_tactical_data(json_part, filename, user_id_from_jwt);
            if (user_id_from_jwt) free(user_id_from_jwt);
            free(json_part);
            free(jwt_token_part);
            if (tactical_data != NULL && tactical_data->is_valid) {
                parsed_result = db_save_tactical_data_and_get_response(tactical_data, filename);
                // Bildirim: adminlere gönder
                cJSON* report_json_obj = parse_tactical_data_to_json(tactical_data);
                char* report_json = cJSON_Print(report_json_obj);
                int sender_privilege = 0;
                if (jwt_token) {
                    jwt_t *jwt_ptr = NULL;
                    if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                        sender_privilege = jwt_get_grant_int(jwt_ptr, "privilege");
                        jwt_free(jwt_ptr);
                    }
                }
                admin_notify_manager_notify_admins(report_json, client_socket, sender_privilege);
                // --- report_id <-> user mapping kodu kaldırıldı ---
                cJSON_Delete(report_json_obj);
                free(report_json);
                free_tactical_data(tactical_data);
            } else {
                parsed_result = malloc(256);
                strcpy(parsed_result, "HATA: JSON tactical data formatına uygun değil");
                if (tactical_data) free_tactical_data(tactical_data);
            }
        } else if (strcmp(command, "ENCRYPTED") == 0 && is_encrypted) {
            PRINTF_LOG("Sifreli JSON parse ediliyor (Tactical Data format)...\n");
            fflush(stdout);
            parsed_result = handle_encrypted_request(filename, content, get_session_key(&client_manager), jwt_token, client_socket, client_ip, 0);        } else if (strcmp(command, "REPORT_QUERY") == 0) {
            PRINTF_LOG("REPORT_QUERY komutu alındı. JWT ile rapor sorgulama başlatılıyor...\n");
            char* jwt_token_part = NULL;
            // content doğrudan JWT token ise
            if (content && strlen(content) > 10) {
                jwt_token_part = strdup(content);
            }
            if (!jwt_token_part) {
                PRINTF_LOG("HATA: REPORT_QUERY mesajında JWT token yok!\n");
                char* error_response = "HATA: REPORT_QUERY mesajında JWT token yok!";
                send(client_socket, error_response, strlen(error_response), 0);
                continue;
            }
            char json_result[32768];
            handle_report_query(jwt_token_part, json_result, sizeof(json_result));
            send(client_socket, json_result, strlen(json_result), 0);
            free(jwt_token_part);
        } else if (command && strcmp(command, "REPLY_QUERY") == 0) {
            PRINTF_LOG("REPLY_QUERY komutu alındı. JWT ile reply sorgulama başlatılıyor...\n");
            char* jwt_token_part = NULL;
            if (content && strlen(content) > 10) {
                jwt_token_part = strdup(content);
            }
            if (!jwt_token_part) {
                PRINTF_LOG("HATA: REPLY_QUERY mesajında JWT token yok!\n");
                char* error_response = "HATA: REPLY_QUERY mesajında JWT token yok!";
                send(client_socket, error_response, strlen(error_response), 0);
                if (command) free(command);
                if (filename) free(filename);
                if (content) free(content);
                continue;
            }
            
            // Büyük yanıtlar için chunked response kullan
            char* json_result = malloc(65536); // Daha büyük buffer
            handle_reply_query(jwt_token_part, json_result, 65536);
            
            PRINTF_LOG("[SERVER][REPLY_QUERY] JSON yanıt uzunluğu: %zu\n", strlen(json_result));
            
            // Eğer yanıt çok büyükse, parça parça gönder
            size_t result_len = strlen(json_result);
            if (result_len > 8192) { // 8KB'den büyükse parça parça gönder
                PRINTF_LOG("[SERVER][REPLY_QUERY] Büyük yanıt parça parça gönderiliyor...\n");
                send_large_encrypted_response(client_socket, json_result);
            } else {
                PRINTF_LOG("[SERVER][REPLY_QUERY] Küçük yanıt tek parça gönderiliyor...\n");
                char* full_response = malloc(result_len + 64);
                snprintf(full_response, result_len + 64, "REPLY_QUERY:%s", json_result);
                send(client_socket, full_response, strlen(full_response), 0);
                free(full_response);
            }
            
            free(json_result);
            free(jwt_token_part);
            if (command) free(command);
            if (filename) free(filename);
            if (content) free(content);
            continue;
        } else {
            parsed_result = malloc(256);
            snprintf(parsed_result, 256, "HATA: Bilinmeyen komut: %s", command);
        }
        if (parsed_result != NULL) {
            send(client_socket, parsed_result, strlen(parsed_result), 0);
            PRINTF_LOG("Parse sonucu gonderildi\n");
            fflush(stdout);
            free(parsed_result);
        }
        if (command) free(command);
        if (filename) free(filename);
        if (content) free(content);
        if (jwt_token) free(jwt_token);
    }

    close(client_socket);
    admin_notify_manager_remove_client(client_socket);
    admin_reply_manager_remove_user(client_socket);
    PRINTF_LOG("Client bağlantısı kapatıldı (Thread: %lu, Toplam istek: %d)\n", 
           current_thread, request_count);
    
    // ECDH temizliği
    cleanup_ecdh_for_connection(&client_manager);
    
    // Thread bilgilerini temizle
    remove_thread_info(current_thread);
    
    PRINTF_LOG("✅ Thread slot serbest kaldı - Queue kontrol ediliyor...\n");
    fflush(stdout);
    
    fflush(stdout);
    return NULL; // void* döndürmek için
}