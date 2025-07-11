#include "listen_manager.h"
#include "logger.h"
#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include "thread_manager.h"

void listen_for_admin_notifications(client_connection_t* conn) {
    extern char jwt_token[];
    char notify_cmd[2048];
    snprintf(notify_cmd, sizeof(notify_cmd), "ADMIN_NOTIFY_LISTEN:%s", jwt_token);
    send(conn->socket, notify_cmd, strlen(notify_cmd), 0);

    char buffer[4096];
    printf("\n[ADMIN] Bildirim dinleme başlatıldı. Sunucudan gelen bildirimler burada gösterilecek.\nÇıkmak için Ctrl+C kullanabilirsiniz.\n\n");
    while (1) {
        ssize_t n = recv(conn->socket, buffer, sizeof(buffer)-1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            printf("\n[ADMIN BILDIRIM] Sunucudan gelen bildirim:\n%s\n", buffer);
        } else if (n == 0) {
            printf("\n[ADMIN] Sunucu bağlantısı kapatıldı.\n");
            break;
        } else {
            perror("[ADMIN] Bildirim okuma hatası");
            break;
        }
    }
}

void listen_report_replies(client_connection_t* conn) {
    extern char jwt_token[];
    char watch_cmd[2048];
    snprintf(watch_cmd, sizeof(watch_cmd), "REPORT_REPLY_WATCH:%s", jwt_token);
    send(conn->socket, watch_cmd, strlen(watch_cmd), 0);

    pthread_t reply_thread;
    pthread_create(&reply_thread, NULL, listen_report_replies_thread, conn);
    pthread_detach(reply_thread);
    int last_count = 0;
    printf("\nGelen admin cevaplarını izleme modunda. Çıkmak için Ctrl+C kullanabilirsiniz.\n");
    LOG_CLIENT_INFO("Report reply watching started");
    while (1) {
        pthread_mutex_lock(&report_reply_mutex);
        if (report_reply_count > last_count) {
            for (int i = last_count; i < report_reply_count; ++i) {
                printf("- Rapor #%d: %s\n", report_replies[i].report_id, report_replies[i].msg);
                LOG_CLIENT_INFO("New report reply received: Report #%d: %s", report_replies[i].report_id, report_replies[i].msg);
            }
            last_count = report_reply_count;
        }
        pthread_mutex_unlock(&report_reply_mutex);
        sleep(1); // 1 saniye bekle
    }
}

