#include "admin_reply_manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <pthread.h>
#include "database.h"
#include "config.h"
#include "json_utils.h"
#include "jwt.h"
#include "logger.h"

static user_socket_map_t user_map[MAX_ACTIVE_USERS];
static int user_map_count = 0;

// Kullanıcı login olduğunda çağrılır
void admin_reply_manager_register_user(int user_id, int user_socket) {
    // Aynı user_id varsa önce sil
    for (int i = 0; i < user_map_count;) {
        if (user_map[i].user_id == user_id) {
            printf("[ADMIN_REPLY][register_user] Eski kayıt siliniyor: user_id=%d, eski_socket=%d\n", user_id, user_map[i].user_socket);
            for (int j = i; j < user_map_count-1; ++j) {
                user_map[j] = user_map[j+1];
            }
            user_map_count--;
            continue;
        }
        i++;
    }
    // Şimdi yeni kaydı ekle
    if (user_map_count < MAX_ACTIVE_USERS) {
        user_map[user_map_count].user_id = user_id;
        user_map[user_map_count].user_socket = user_socket;
        user_map_count++;
        printf("[ADMIN_REPLY][register_user] Yeni kayıt: user_id=%d, user_socket=%d, toplam=%d\n", user_id, user_socket, user_map_count);
    } else {
        printf("[ADMIN_REPLY][register_user] HATA: MAX_ACTIVE_USERS aşıldı!\n");
    }
}

// Kullanıcı bağlantısı kopunca çağrılır
void admin_reply_manager_remove_user(int user_socket) {
    printf("[ADMIN_REPLY][remove_user] Çağrıldı: user_socket=%d, thread_id=%lu\n", user_socket, pthread_self());
    for (int i = 0; i < user_map_count;) {
        if (user_map[i].user_socket == user_socket) {
            printf("[ADMIN_REPLY][remove_user] Siliniyor: user_id=%d, user_socket=%d\n", user_map[i].user_id, user_map[i].user_socket);
            for (int j = i; j < user_map_count-1; ++j) {
                user_map[j] = user_map[j+1];
            }
            user_map_count--;
            continue;
        }
        i++;
    }
    printf("[ADMIN_REPLY][remove_user] Kalan kayıt sayısı: %d\n", user_map_count);
}

// Admin reply fonksiyonu: report_id'den user_id'yi bul, aktifse mesajı ilet
bool admin_reply_manager_send_reply(int report_id, const char* message, int admin_socket) {
    printf("[ADMIN_REPLY][send_reply] Çağrıldı: report_id=%d, message=%s, admin_socket=%d\n", report_id, message, admin_socket);
    
    // 1. Admin'in user_id'sini bul (reply'ı gönderen kişi)
    int admin_user_id = -1;
    for (int i = 0; i < user_map_count; ++i) {
        if (user_map[i].user_socket == admin_socket) {
            admin_user_id = user_map[i].user_id;
            break;
        }
    }
    if (admin_user_id == -1) {
        printf("[ADMIN_REPLY][send_reply] HATA: admin_socket %d için user_id bulunamadı!\n", admin_socket);
        return false;
    }
    printf("[ADMIN_REPLY][send_reply] admin_socket=%d -> admin_user_id=%d\n", admin_socket, admin_user_id);
    
    // 2. REPORTS tablosundan report sahibinin user_id'sini bul
    report_t report;
    if (db_get_report_by_id(report_id, &report) != 0) {
        printf("[ADMIN_REPLY][send_reply] HATA: report_id %d için kayıt bulunamadı!\n", report_id);
        return false;
    }
    int report_owner_user_id = report.user_id;
    printf("[ADMIN_REPLY][send_reply] report_id=%d -> report_owner_user_id=%d\n", report_id, report_owner_user_id);
    // 3. Report sahibinin aktif bağlantısını bul
    int user_socket = -1;
    for (int i = 0; i < user_map_count; ++i) {
        if (user_map[i].user_id == report_owner_user_id) {
            user_socket = user_map[i].user_socket;
            break;
        }
    }
    if (user_socket == -1) {
        printf("[ADMIN_REPLY][send_reply] report_owner_user_id %d için aktif bağlantı yok, veri tabanına kaydedildi (offline)\n", report_owner_user_id);
        reply_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.user_id = admin_user_id;  // Reply'ı gönderen admin'in user_id'si
        reply.report_id = report_id;
        strncpy(reply.message, message, sizeof(reply.message) - 1);
        reply.timestamp = time(NULL);
        db_insert_reply(&reply);
        return false;
    }
    // 4. Mesajı report sahibine ilet
    char reply_msg[1024];
    snprintf(reply_msg, sizeof(reply_msg), "REPORT_REPLY:%d:%s\n", report_id, message);
    ssize_t sent = send(user_socket, reply_msg, strlen(reply_msg), 0);
    printf("[ADMIN_REPLY][send_reply] send() çağrıldı: user_socket=%d, sent=%zd\n", user_socket, sent);
    if (sent > 0) {
        printf("[ADMIN_REPLY][send_reply] Report %d için kullanıcıya dönüt gönderildi (socket=%d, sent=%zd)\n", report_id, user_socket, sent);
        reply_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.user_id = admin_user_id;  // Reply'ı gönderen admin'in user_id'si
        reply.report_id = report_id;
        strncpy(reply.message, message, sizeof(reply.message) - 1);
        reply.timestamp = time(NULL);
        db_insert_reply(&reply);
        return true;
    } else {
        perror("[ADMIN_REPLY][send_reply] send hatası");
        return false;
    }
}

// Admin reply işlemini yöneten handler fonksiyonu
void handle_reply_report(const char* decrypted_json, const char* jwt_token, int client_socket, char* out, size_t out_size) {
    PRINTF_LOG("[DEBUG] handle_reply_report çağrıldı\n");
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
            snprintf(out, out_size, "HATA: Admin kullanıcı kimliği belirlenemedi");
            free(reply_data);
            return;
        }
        // admin_reply_t'yi reply_t'ye dönüştür
        reply_t db_reply;
        db_reply.user_id = admin_user_id;  // ÖNEMLİ: Admin'in user_id'si kullanılıyor
        db_reply.report_id = reply_data->report_id;
        strncpy(db_reply.message, reply_data->msg, sizeof(db_reply.message) - 1);
        db_reply.message[sizeof(db_reply.message) - 1] = '\0';
        db_reply.timestamp = time(NULL);
        // Reply sahibine bildirim gönder (admin_reply_manager kullanarak)
        admin_reply_manager_send_reply(reply_data->report_id, reply_data->msg, client_socket);

        free(reply_data);
    } else {
        snprintf(out, out_size, "HATA: Admin reply verisi geçersiz format");
        if (reply_data) free(reply_data);
    }
}
