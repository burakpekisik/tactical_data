#include <sys/socket.h>
#include "admin_notify_manager.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "logger.h"
#include "config.h"

static connected_client_t clients[MAX_CLIENTS];
static int client_count = 0;

void admin_notify_manager_init(void) {
    client_count = 0;
    memset(clients, 0, sizeof(clients));
}

void admin_notify_manager_add_client(int socket_fd, int privilege, const char* username) {
    // Aynı socket_fd zaten kayıtlıysa tekrar ekleme
    for (int i = 0; i < client_count; ++i) {
        if (clients[i].socket_fd == socket_fd) {
            PRINTF_LOG("[ADMIN_NOTIFY] UYARI: socket_fd %d zaten kayıtlı, tekrar eklenmedi.\n", socket_fd);
            return;
        }
    }
    if (client_count >= MAX_CLIENTS) return;
    clients[client_count].socket_fd = socket_fd;
    clients[client_count].privilege = privilege;
    strncpy(clients[client_count].username, username, sizeof(clients[client_count].username)-1);
    clients[client_count].username[sizeof(clients[client_count].username)-1] = '\0';
    client_count++;
}

void admin_notify_manager_remove_client(int socket_fd) {
    for (int i = 0; i < client_count; ++i) {
        if (clients[i].socket_fd == socket_fd) {
            for (int j = i; j < client_count-1; ++j) {
                clients[j] = clients[j+1];
            }
            client_count--;
            break;
        }
    }
}

void admin_notify_manager_notify_admins(const char* report_json, int sender_socket, int sender_privilege) {
    printf("[DEBUG] admin_notify_manager_notify_admins çağrıldı! sender_socket=%d, sender_privilege=%d\n", sender_socket, sender_privilege);
    PRINTF_LOG("[ADMIN_NOTIFY] Bildirim fonksiyonu çağrıldı. sender_socket=%d, sender_privilege=%d\n", sender_socket, sender_privilege);
    PRINTF_LOG("[ADMIN_NOTIFY] Bildirim içeriği: %s\n", report_json);
    for (int i = 0; i < client_count; ) {
        PRINTF_LOG("[ADMIN_NOTIFY] Kontrol: client[%d] socket_fd=%d, privilege=%d\n", i, clients[i].socket_fd, clients[i].privilege);
        if (clients[i].privilege == 1 && clients[i].socket_fd != sender_socket) {
            PRINTF_LOG("[ADMIN_NOTIFY] Admin socket %d'ye bildirim gönderiliyor...\n", clients[i].socket_fd);
            char msg_with_newline[2048];
            snprintf(msg_with_newline, sizeof(msg_with_newline), "%s\n", report_json);
            ssize_t sent = send(clients[i].socket_fd, msg_with_newline, strlen(msg_with_newline), 0);
            printf("[DEBUG] admin_notify_manager_notify_admins: send() -> sent=%zd (socket_fd=%d)\n", sent, clients[i].socket_fd);
            if (sent == -1) {
                perror("[ADMIN_NOTIFY] send hatası");
                PRINTF_LOG("[ADMIN_NOTIFY] Admin socket %d bağlantısı hatalı, listeden çıkarılıyor.\n", clients[i].socket_fd);
                admin_notify_manager_remove_client(clients[i].socket_fd);
                // Silindiği için aynı indexte tekrar döngüye devam et
                continue;
            }
            PRINTF_LOG("[ADMIN_NOTIFY] send sonucu: %zd\n", sent);
        }
        i++;
    }
}

void admin_notify_manager_cleanup(void) {
    client_count = 0;
}
