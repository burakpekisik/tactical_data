#include "client_notify_threads.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include "admin_notify_manager.h"
#include "logger.h"

void* admin_notify_listen_thread(void* arg) {
    struct notify_thread_args* args = (struct notify_thread_args*)arg;
    int client_socket = args->client_socket;
    int privilege = args->privilege;
    char username[128];
    strncpy(username, args->username, sizeof(username)-1);
    username[sizeof(username)-1] = '\0';
    free(args);

    char buffer[4096];
    while (1) {
        ssize_t n = recv(client_socket, buffer, sizeof(buffer)-1, 0);
        if (n <= 0) break;
        // Admin dinleme modunda başka veri beklenmiyor, sadece bağlantı açık tutuluyor
    }
    close(client_socket);
    admin_notify_manager_remove_client(client_socket);
    PRINTF_LOG("[ADMIN_NOTIFY] Admin dinleme bağlantısı kapatıldı (socket %d)\n", client_socket);
    return NULL;
}

void* report_reply_watch_thread(void* arg) {
    int client_socket = *(int*)arg;
    free(arg);
    // Sadece bağlantı açık tutulacak, veri beklenmiyor
    char buffer[1024];
    while (1) {
        ssize_t n = recv(client_socket, buffer, sizeof(buffer)-1, 0);
        if (n <= 0) break;
    }
    close(client_socket);
    // Mapping silme işlemi ana thread'de yapılmış olabilir
    return NULL;
}
