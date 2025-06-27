#include "admin_reply_manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <pthread.h>
#include "database.h"

#define MAX_ACTIVE_USERS 128

typedef struct {
    int user_id;
    int user_socket;
} user_socket_map_t;

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
    // 1. REPORTS tablosundan user_id'yi bul
    report_t report;
    if (db_get_report_by_id(report_id, &report) != 0) {
        printf("[ADMIN_REPLY][send_reply] HATA: report_id %d için kayıt bulunamadı!\n", report_id);
        return false;
    }
    int user_id = report.user_id;
    printf("[ADMIN_REPLY][send_reply] report_id=%d -> user_id=%d\n", report_id, user_id);
    // 2. Aktif user_id <-> socket mapping'den bul
    int user_socket = -1;
    for (int i = 0; i < user_map_count; ++i) {
        if (user_map[i].user_id == user_id) {
            user_socket = user_map[i].user_socket;
            break;
        }
    }
    if (user_socket == -1) {
        printf("[ADMIN_REPLY][send_reply] user_id %d için aktif bağlantı yok, veri tabanına kaydedildi (offline)\n", user_id);
        reply_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.user_id = user_id;
        reply.report_id = report_id;
        strncpy(reply.message, message, sizeof(reply.message) - 1);
        reply.timestamp = time(NULL);
        db_insert_reply(&reply);
        return false;
    }
    // 3. Mesajı ilet
    char reply_msg[1024];
    snprintf(reply_msg, sizeof(reply_msg), "REPORT_REPLY:%d:%s\n", report_id, message);
    ssize_t sent = send(user_socket, reply_msg, strlen(reply_msg), 0);
    printf("[ADMIN_REPLY][send_reply] send() çağrıldı: user_socket=%d, sent=%zd\n", user_socket, sent);
    if (sent > 0) {
        printf("[ADMIN_REPLY][send_reply] Report %d için kullanıcıya dönüt gönderildi (socket=%d, sent=%zd)\n", report_id, user_socket, sent);
        reply_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.user_id = user_id;
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
