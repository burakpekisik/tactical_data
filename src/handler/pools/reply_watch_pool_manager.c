#include "handle_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "queue_manager.h"
#include "pool_manager.h"
#include "client_notify_threads.h"
#include "thread_monitor.h"
#include "admin_reply_manager.h"
#include "logger.h"

thread_pool_t reply_watch_pool;

// Wrapper fonksiyon: report_reply_watch_thread'i pool ile kullanmak için
void reply_watch_task(void* arg) {
    struct { int client_socket; int user_id; } *params = arg;
    PRINTF_LOG("[DEBUG][reply_watch_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][reply_watch_task] arg is NULL!\n");
        return;
    }
    pthread_t tid = pthread_self();
    add_thread_info(tid, params->client_socket, "N/A", params->user_id, "reply_watch_task");
    // Kayıt işlemi (isteğe bağlı, user_id ile)
    admin_reply_manager_register_user(params->user_id, params->client_socket);
    // Asıl izleme thread'i
    report_reply_watch_thread(&(params->client_socket));
    // Çıkışta temizlik
    remove_thread_info(pthread_self());
    free(params);
}

void init_reply_watch_pool() {
    thread_pool_init(&reply_watch_pool, 4, 64); // 4 thread, 64 kuyruk kapasitesi (isteğe göre ayarla)
}
