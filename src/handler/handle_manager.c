#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
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
#include "chat_protocol.h"
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
#include "handle_manager.h"
#include "config.h"
#include "chat_utils.h"
#include "chat_handler.h"
#include "broadcast_manager.h"
#include "large_response.h"
#include "tactical_data_handler.h"
#include "location_handler.h"
#include "client_notify_threads.h"
#include "info_handler.h"
#include "login_user.h"
#include "queue_manager.h"
#include "pool_manager.h"

// Global chat room state (only defined here)
server_chat_room_t server_rooms[MAX_CHAT_ROOMS];
int server_room_count = 0;

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

char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token, int client_socket, const char* client_ip, int client_port) {
    PRINTF_LOG("[DEBUG] handle_encrypted_request: filename=%s, client_socket=%d, client_ip=%s, client_port=%d\n", filename, client_socket, client_ip ? client_ip : "(null)", client_port);

    if (!jwt_token) {
        PRINTF_LOG("[ERROR] handle_encrypted_request: jwt_token NULL\n");
        return strdup("{\"error\":\"JWT token NULL\"}");
    }

    PRINTF_LOG("handle_encrypted_request çağrıldı\n");
    // PRINTF_LOG("ENCRYPTED content: %s\n", encrypted_content);

    if (session_key == NULL || encrypted_content == NULL) {
        PRINTF_LOG("[ERROR] handle_encrypted_request: session_key veya encrypted_content NULL\n");
        return strdup("{\"error\":\"Session key veya encrypted content NULL\"}");
    }

    char* error_msg = NULL;
    char* decrypted_json = decrypt_protocol_payload(encrypted_content, session_key, &error_msg);
    if (decrypted_json == NULL) {
        if (error_msg) {
            return error_msg;
        } else {
            char* fallback = malloc(128);
            strcpy(fallback, "HATA: Decryption bilinmeyen hata");
            return fallback;
        }
    }
    // PRINTF_LOG("[DEBUG] Decrypted JSON: %s\n", decrypted_json);

    // --- CHAT ACTION ŞİFRELİ YANIT ---
    cJSON* root = cJSON_Parse(decrypted_json);

    cJSON* action_item = cJSON_GetObjectItem(root, "action");
    PRINTF_LOG("handle_encrypted_request: action_item=%s\n", cJSON_Print(action_item));
    if (action_item && cJSON_IsString(action_item)) {
        const char* action = action_item->valuestring;
        PRINTF_LOG("[CHAT] handle_encrypted_request: action=%s\n", action);
        pool_result_t result;
        pthread_mutex_init(&result.mutex, NULL);
        pthread_cond_init(&result.cond, NULL);
        result.result = NULL;
        result.ready = 0;
        if (strcmp(action, "chat_create_room") == 0) {
            PRINTF_LOG("[CHAT] handle_encrypted_request: chat_create_room çağrılıyor\n");
            struct { char* decrypted_json; const char* jwt_token; pool_result_t* result; const uint8_t* session_key; } *params = malloc(sizeof(*params));
            params->decrypted_json = strdup(decrypted_json);
            params->jwt_token = jwt_token;
            params->result = &result;
            params->session_key = session_key;
            thread_pool_submit(&chat_create_room_pool, chat_create_room_task, params);
            pthread_mutex_lock(&result.mutex);
            while (!result.ready) pthread_cond_wait(&result.cond, &result.mutex);
            pthread_mutex_unlock(&result.mutex);
            pthread_mutex_destroy(&result.mutex);
            pthread_cond_destroy(&result.cond);
            free(decrypted_json); cJSON_Delete(root);
            return result.result;
        } else if (strcmp(action, "chat_list_rooms") == 0) {
            PRINTF_LOG("[CHAT] handle_encrypted_request: chat_list_rooms çağrılıyor\n");
            struct { char* decrypted_json; const char* jwt_token; pool_result_t* result; const uint8_t* session_key; } *params = malloc(sizeof(*params));
            params->decrypted_json = strdup(decrypted_json);
            params->jwt_token = jwt_token;
            params->result = &result;
            params->session_key = session_key;
            thread_pool_submit(&chat_list_rooms_pool, chat_list_rooms_task, params);
            pthread_mutex_lock(&result.mutex);
            while (!result.ready) pthread_cond_wait(&result.cond, &result.mutex);
            pthread_mutex_unlock(&result.mutex);
            pthread_mutex_destroy(&result.mutex);
            pthread_cond_destroy(&result.cond);
            free(decrypted_json); cJSON_Delete(root);
            return result.result;
        } else if (strcmp(action, "chat_join_room") == 0) {
            PRINTF_LOG("[CHAT] handle_encrypted_request: chat_join_room çağrılıyor\n");
            struct { char* decrypted_json; const char* jwt_token; int client_socket; pool_result_t* result; const uint8_t* session_key; } *params = malloc(sizeof(*params));
            params->decrypted_json = strdup(decrypted_json);
            params->jwt_token = jwt_token;
            params->client_socket = client_socket;
            params->result = &result;
            params->session_key = session_key;
            thread_pool_submit(&chat_join_room_pool, chat_join_room_task, params);
            pthread_mutex_lock(&result.mutex);
            while (!result.ready) pthread_cond_wait(&result.cond, &result.mutex);
            pthread_mutex_unlock(&result.mutex);
            pthread_mutex_destroy(&result.mutex);
            pthread_cond_destroy(&result.cond);
            free(decrypted_json); cJSON_Delete(root);
            return result.result;
        } else if (strcmp(action, "chat_get_messages") == 0) {
            PRINTF_LOG("[CHAT] handle_encrypted_request: chat_get_messages çağrılıyor\n");
            struct { char* decrypted_json; pool_result_t* result; const uint8_t* session_key; } *params = malloc(sizeof(*params));
            params->decrypted_json = strdup(decrypted_json);
            params->result = &result;
            params->session_key = session_key;
            thread_pool_submit(&chat_get_messages_pool, chat_get_messages_task, params);
            pthread_mutex_lock(&result.mutex);
            while (!result.ready) pthread_cond_wait(&result.cond, &result.mutex);
            pthread_mutex_unlock(&result.mutex);
            pthread_mutex_destroy(&result.mutex);
            pthread_cond_destroy(&result.cond);
            free(decrypted_json); cJSON_Delete(root);
            return result.result;
        } else if (strcmp(action, "chat_send_message") == 0) {
            PRINTF_LOG("[CHAT] handle_encrypted_request: chat_send_message çağrılıyor\n");
            struct { char* decrypted_json; const char* jwt_token; int client_socket; pool_result_t* result; const uint8_t* session_key; } *params = malloc(sizeof(*params));
            params->decrypted_json = strdup(decrypted_json);
            params->jwt_token = jwt_token;
            params->client_socket = client_socket;
            params->result = &result;
            params->session_key = session_key;
            thread_pool_submit(&chat_send_message_pool, chat_send_message_task, params);
            pthread_mutex_lock(&result.mutex);
            while (!result.ready) pthread_cond_wait(&result.cond, &result.mutex);
            pthread_mutex_unlock(&result.mutex);
            pthread_mutex_destroy(&result.mutex);
            pthread_cond_destroy(&result.cond);
            free(decrypted_json); cJSON_Delete(root);
            return result.result;
        } else if (strcmp(action, "chat_leave_room") == 0) {
            PRINTF_LOG("[CHAT] handle_encrypted_request: chat_leave_room çağrılıyor\n");
            struct { char* decrypted_json; int client_socket; pool_result_t* result; const uint8_t* session_key; } *params = malloc(sizeof(*params));
            params->decrypted_json = strdup(decrypted_json);
            params->client_socket = client_socket;
            params->result = &result;
            params->session_key = session_key;
            thread_pool_submit(&chat_leave_room_pool, chat_leave_room_task, params);
            pthread_mutex_lock(&result.mutex);
            while (!result.ready) pthread_cond_wait(&result.cond, &result.mutex);
            pthread_mutex_unlock(&result.mutex);
            pthread_mutex_destroy(&result.mutex);
            pthread_cond_destroy(&result.cond);
            free(decrypted_json); cJSON_Delete(root);
            return result.result;
        } else {
            PRINTF_LOG("[CHAT] handle_encrypted_request: Bilinmeyen action: %s\n", action);
            // Bilinmeyen action için hata dön
            char* error_json = strdup("{\"error\":\"Bilinmeyen chat action\"}");
            free(decrypted_json);
            cJSON_Delete(root);
            char* encrypted_result = encrypt_and_format_response(error_json, session_key, action);
            free(error_json);
            return encrypted_result;
        }
    }
    
    if (strcmp(filename, "INFO") == 0) {
        char* jwt_from_json = NULL;
        if (root) {
            cJSON* jwt_item = cJSON_GetObjectItem(root, "jwt");
            if (jwt_item && cJSON_IsString(jwt_item)) {
                jwt_from_json = jwt_item->valuestring;
            }
        }
        char* plain_result = malloc(65536);
        if (jwt_from_json) {
            int info_ret = handle_info_request(jwt_from_json, plain_result, 65536);
            if (info_ret == 0) {
                PRINTF_LOG("[SERVER][ENCRYPTED] INFO işlendi, yanıt uzunluğu: %zu\n", strlen(plain_result));
            } else {
                snprintf(plain_result, 65536, "{\"error\":\"Bilgi alınamadı\"}");
            }
        } else {
            snprintf(plain_result, 65536, "{\"error\":\"JWT bulunamadı\"}");
        }
        if (root) cJSON_Delete(root);
        send_or_format_large_encrypted_response(client_socket, plain_result, session_key, filename);
        free(plain_result);
        free(decrypted_json);
        return NULL;
    }

    // Eğer dosya adı REPORT_QUERY, REPLY_QUERY veya QUERY_MY_REPLIES ise, rapor sorgulama işlemi yap
    if (strcmp(filename, "REPORT_QUERY") == 0 || strcmp(filename, "REPLY_QUERY") == 0 || strcmp(filename, "QUERY_MY_REPLIES") == 0 || strcmp(filename, "QUERY_REPLIES_ONE_REPORT") == 0) {
        pool_result_t result;
        pthread_mutex_init(&result.mutex, NULL);
        pthread_cond_init(&result.cond, NULL);
        result.result = NULL;
        result.ready = 0;

        char* jwt_from_json = NULL;
        if (root) {
            cJSON* jwt_item = cJSON_GetObjectItem(root, "jwt");
            if (jwt_item && cJSON_IsString(jwt_item)) {
                jwt_from_json = jwt_item->valuestring;
            }
        }

        if (strcmp(filename, "REPORT_QUERY") == 0) {
            struct { char* jwt_token; char* plain_result; size_t result_size; pool_result_t* result; const uint8_t* session_key; int client_socket; } *params = malloc(sizeof(*params));
            params->jwt_token = jwt_from_json ? strdup(jwt_from_json) : NULL;
            params->plain_result = malloc(65536);
            params->result_size = 65536;
            params->result = &result;
            params->session_key = session_key;
            params->client_socket = client_socket;
            thread_pool_submit(&report_query_pool, report_query_task, params);
        } else if (strcmp(filename, "REPLY_QUERY") == 0) {
            struct { char* jwt_token; char* plain_result; size_t result_size; pool_result_t* result; const uint8_t* session_key; int client_socket; } *params = malloc(sizeof(*params));
            params->jwt_token = jwt_from_json ? strdup(jwt_from_json) : NULL;
            params->plain_result = malloc(65536);
            params->result_size = 65536;
            params->result = &result;
            params->session_key = session_key;
            params->client_socket = client_socket;
            thread_pool_submit(&reply_query_pool, reply_query_task, params);
        } else if (strcmp(filename, "QUERY_MY_REPLIES") == 0) {
            struct { char* jwt_token; char* plain_result; size_t result_size; pool_result_t* result; const uint8_t* session_key; int client_socket; } *params = malloc(sizeof(*params));
            params->jwt_token = jwt_from_json ? strdup(jwt_from_json) : NULL;
            params->plain_result = malloc(65536);
            params->result_size = 65536;
            params->result = &result;
            params->session_key = session_key;
            params->client_socket = client_socket;
            thread_pool_submit(&query_my_replies_pool, query_my_replies_task, params);
        } else if (strcmp(filename, "QUERY_REPLIES_ONE_REPORT") == 0) {
            struct { char* jwt_token; cJSON* root; char* plain_result; size_t result_size; pool_result_t* result; const uint8_t* session_key; int client_socket; } *params = malloc(sizeof(*params));
            params->jwt_token = jwt_from_json ? strdup(jwt_from_json) : NULL;
            params->root = root ? cJSON_Duplicate(root, 1) : NULL;
            params->plain_result = malloc(65536);
            params->result_size = 65536;
            params->result = &result;
            params->session_key = session_key;
            params->client_socket = client_socket;
            thread_pool_submit(&query_replies_one_report_pool, query_replies_one_report_task, params);
        }

        pthread_mutex_lock(&result.mutex);
        while (!result.ready) pthread_cond_wait(&result.cond, &result.mutex);
        pthread_mutex_unlock(&result.mutex);
        pthread_mutex_destroy(&result.mutex);
        pthread_cond_destroy(&result.cond);
        if (root) cJSON_Delete(root);
        free(decrypted_json);
        // result.result is already encrypted and sent in the task, or NULL if error
        return result.result;
    }

    if(strcmp(filename, "INSERT_LOCATION") == 0 || strcmp(filename, "SELECT_LOCATION_OF_USER") == 0 || strcmp(filename, "SELECT_LATEST_LOCATIONS_BY_UNIT") == 0 || strcmp(filename, "SELECT_LATEST_LOCATIONS_ALL_USERS") == 0 || strcmp(filename, "SELECT_LATEST_LOCATIONS_ALL_USERS_BY_RADIUS") == 0 || strcmp(filename, "SELECT_LATEST_LOCATIONS_MY_UNIT") == 0) {
        cJSON* root_location = cJSON_Parse(decrypted_json);

        if (!root_location) {
            PRINTF_LOG("DEBUG: cJSON_Parse failed! Input: %s\n", decrypted_json);
        }

        char* plain_result = NULL;
        if(strcmp(filename, "INSERT_LOCATION") == 0) {
            plain_result = handle_insert_location(root_location);
        } else if(strcmp(filename, "SELECT_LOCATION_OF_USER") == 0) {
            plain_result = handle_select_location_of_user(root);
        } else if(strcmp(filename, "SELECT_LATEST_LOCATIONS_BY_UNIT") == 0) {
            plain_result = handle_select_latest_locations_by_unit(root);
        } else if(strcmp(filename, "SELECT_LATEST_LOCATIONS_ALL_USERS") == 0) {
            plain_result = handle_select_latest_locations_all_users(root);
        } else if(strcmp(filename, "SELECT_LATEST_LOCATIONS_ALL_USERS_BY_RADIUS") == 0) {
            plain_result = handle_select_latest_locations_all_users_by_radius(root);
        } else if (strcmp(filename, "SELECT_LATEST_LOCATIONS_MY_UNIT") == 0) {
            plain_result = handle_select_latest_locations_of_my_unit(root);
        }
        send_or_format_large_encrypted_response(client_socket, plain_result, session_key, filename);
        if (plain_result) free(plain_result);
        if (root) cJSON_Delete(root);
        free(decrypted_json);
        return NULL;
    }

    
    if (strcmp(filename, "REPLY_REPORT") == 0) {
        char plain_result[2048];
        if (jwt_token) {
            handle_reply_report(decrypted_json, jwt_token, client_socket, plain_result, sizeof(plain_result));
            PRINTF_LOG("[SERVER][ENCRYPTED] REPLY_REPORT işlendi, yanıt: %s\n", plain_result);
        } else {
            snprintf(plain_result, sizeof(plain_result), "{\"error\":\"JWT bulunamadı\"}");
        }
        char* result = strdup(plain_result);
        free(decrypted_json);
        return result;
    } else {
        char plain_result[2048];
        if (jwt_token) {
            handle_encrypted_tactical_data(decrypted_json, jwt_token, filename, client_socket, client_ip, client_port, plain_result, sizeof(plain_result));
            PRINTF_LOG("[SERVER][ENCRYPTED] TACTICAL_DATA işlendi, yanıt: %s\n", plain_result);
        } else {
            snprintf(plain_result, sizeof(plain_result), "{\"error\":\"JWT bulunamadı\"}");
        }
        char* result = strdup(plain_result);
        free(decrypted_json);
        return result;
    }
    return NULL; // Bu noktaya gelinmemeli, hata durumunda NULL dönebiliriz
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
        PRINTF_LOG("[LOGIN] LOGIN isteği alındı: %s\n", buffer);
        handle_login_request(buffer, client_socket, current_thread);
        PRINTF_LOG("[LOGIN] LOGIN isteği işleme tamamlandı\n");
        return NULL;
    }
    
    // ECDH için anahtar değişimi yap
    connection_manager_t client_manager;
    uint8_t client_public_key[ECC_PUB_KEY_SIZE];
    if (handle_ecdh_key_exchange(client_socket, current_thread, &client_manager, client_public_key, buffer, bytes_received) != 0) {
        return NULL;
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
        // PRINTF_LOG("[DEBUG] handle_client: gelen mesaj: %s\n", buffer);

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
                    PRINTF_LOG("[HELLO] HELLO ile mapping güncellendi: user_id=%d, socket=%d\n", user_id, client_socket);
                }
                jwt_free(jwt_ptr);
            }
            continue;
        }

        // --- PING/PING_TEST komutu ---
        if (strncmp(bufptr, "PING", 4) == 0 || strncmp(bufptr, "PING_TEST", 9) == 0) {
            PRINTF_LOG("[PING] PING/PING_TEST komutu alındı, yanıt gönderiliyor...\n");
            const char* pong_response = "PONG";
            send(client_socket, pong_response, strlen(pong_response), 0);
            continue;
        }

        size_t buflen = strlen(bufptr);
        while (buflen > 0 && (bufptr[buflen-1] == '\n' || bufptr[buflen-1] == ' ' || bufptr[buflen-1] == '\t')) {
            bufptr[buflen-1] = '\0';
            buflen--;
        }

        if (strncmp(bufptr, "REPORT_REPLY_WATCH:", 19) == 0) {
            // JWT token'ı ayıkla
            const char* jwt_token = bufptr + 19;
            while (*jwt_token == ' ' || *jwt_token == '\t' || *jwt_token == '\n' || *jwt_token == ':') jwt_token++;
            int user_id = -1;
            if (jwt_token && strlen(jwt_token) > 10) {
                jwt_t *jwt_ptr = NULL;
                if (jwt_decode(&jwt_ptr, jwt_token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
                    const char* sub = jwt_get_grant(jwt_ptr, "sub");
                    if (sub) user_id = atoi(sub);
                    jwt_free(jwt_ptr);
                }
            }
            if (user_id > 0) {
                admin_reply_manager_register_user(user_id, client_socket);
                PRINTF_LOG("[REPORT_REPLY_WATCH] REPORT_REPLY_WATCH kaydı: user_id=%d, socket=%d\n", user_id, client_socket);
                send(client_socket, "REPORT_REPLY_WATCH_OK\n", 23, 0);
                // Yeni thread pool task başlat
                struct { int client_socket; int user_id; } *params = malloc(sizeof(*params));
                params->client_socket = client_socket;
                params->user_id = user_id;
                thread_pool_submit(&reply_watch_pool, reply_watch_task, params);
                remove_thread_info(current_thread);
                return NULL;
            } else {
                send(client_socket, "HATA: Gecersiz veya eksik JWT token\n", 34, 0);
            }
            continue;
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
            PRINTF_LOG("[ADMIN_NOTIFY_LISTEN] ADMIN_NOTIFY_LISTEN komutu alındı, socket %d admin olarak kaydedildi (privilege=%d, username=%s)\n", client_socket, privilege, username);
            // Yeni thread başlat
            struct notify_thread_args* args = malloc(sizeof(struct notify_thread_args));
            args->client_socket = client_socket;
            args->privilege = privilege;
            strncpy(args->username, username, sizeof(args->username)-1);
            args->username[sizeof(args->username)-1] = '\0';
            pthread_t t;
            pthread_create(&t, NULL, admin_notify_listen_thread, args);
            pthread_detach(t);
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
        int parse_error = 0;
        // ENCRYPTED mesajı için özel parse
        if (strncmp(buffer, "ENCRYPTED:", 10) == 0) {
            if (parse_encrypted_protocol_message(buffer, &command, &filename, &content, &jwt_token) != 0) {
                char *error_response = "HATA: Gecersiz ENCRYPTED protokol formati. Format: ENCRYPTED:FILENAME:HEXDATA:JWT";
                send(client_socket, error_response, strlen(error_response), 0);
                parse_error = 1;
            } else {
                is_encrypted = 1;
            }
        } else {
            // Diğer komutlar için standart parse fonksiyonu kullanılabilir
            if (parse_protocol_message(buffer, &command, &filename, &content) != 0) {
                char *error_response = "HATA: Gecersiz protokol formati. Format: COMMAND:FILENAME:CONTENT";
                send(client_socket, error_response, strlen(error_response), 0);
                parse_error = 1;
            }
        }
        // PRINTF_LOG("[DEBUG] Protokol mesajı parse edildi: command=%s, filename=%s, content=%s, jwt_token=%s\n", 
            //    command ? command : "(null)", 
            //    filename ? filename : "(null)", 
            //    content ? content : "(null)", 
            //    jwt_token ? jwt_token : "(null)");

        // Eğer parse hatası olduysa veya command NULL ise güvenli şekilde devam etme
        if (parse_error || command == NULL || filename == NULL || content == NULL) {
            PRINTF_LOG("[ERROR] Protokol parse hatası veya eksik alan: command=%s, filename=%s, content=%s\n",
                command ? command : "(null)",
                filename ? filename : "(null)",
                content ? content : "(null)");
            if (command) free(command);
            if (filename) free(filename);
            if (content) free(content);
            if (jwt_token) free(jwt_token);
            continue;
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
            PRINTF_LOG("Sifreli JSON parse ediliyor...\n");
            // PRINTF_LOG("[DEBUG] ENCRYPTED content: %s\n", content);

            PRINTF_LOG("[DEBUG] ENCRYPTED content uzunluğu: %zu\n", strlen(content));


            fflush(stdout);
            parsed_result = handle_encrypted_request(filename, content, get_session_key(&client_manager), jwt_token, client_socket, client_ip, 0);        
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

// --- Yardımcı: AES ile şifrele ve hex formatla ---
char* encrypt_and_format_response(const char* plain_json, const uint8_t* session_key, const char* action_name) {
    PRINTF_LOG("encrypt_and_format_response çağrıldı\n");
    // PRINTF_LOG("plain_json: %s\n", plain_json);
    uint8_t iv[CRYPTO_IV_SIZE];
    generate_random_iv(iv);
    crypto_result_t* encrypted = encrypt_data(plain_json, session_key, iv);
    if (!encrypted || !encrypted->success) {
        PRINTF_LOG("[CHAT][ERROR] Yanıt şifrelenemedi\n");
        if (encrypted) free_crypto_result(encrypted);
        return strdup("HATA: Yanıt şifrelenemedi");
    }
    size_t combined_length = CRYPTO_IV_SIZE + encrypted->length;
    uint8_t* combined_data = malloc(combined_length);
    memcpy(combined_data, iv, CRYPTO_IV_SIZE);
    memcpy(combined_data + CRYPTO_IV_SIZE, encrypted->data, encrypted->length);
    char* hex_data = bytes_to_hex(combined_data, combined_length);
    PRINTF_LOG("IV (hex): ");
    for (int i = 0; i < CRYPTO_IV_SIZE; i++) PRINTF_LOG("%02X", iv[i]);
    PRINTF_LOG("\nCiphertext uzunluğu: %zu\n", encrypted->length);
    PRINTF_LOG("Hex data uzunluğu: %zu\n", strlen(hex_data));
    free(combined_data);
    free_crypto_result(encrypted);
    size_t total_size = strlen("ENCRYPTED:") + strlen(action_name) + 1 + strlen(hex_data) + 1;
    char* formatted = malloc(total_size);
    snprintf(formatted, total_size, "ENCRYPTED:%s:%s", action_name, hex_data);
    // PRINTF_LOG("ENCRYPTED yanıt: %s\n", formatted);
    free(hex_data);
    return formatted;
}