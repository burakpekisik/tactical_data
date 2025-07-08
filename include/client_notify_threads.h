#ifndef CLIENT_NOTIFY_THREADS_H
#define CLIENT_NOTIFY_THREADS_H
#include <pthread.h>

struct notify_thread_args {
    int client_socket;
    int privilege;
    char username[128];
};

void* admin_notify_listen_thread(void* arg);
void* report_reply_watch_thread(void* arg);

#endif // CLIENT_NOTIFY_THREADS_H
