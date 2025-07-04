#ifndef CHAT_LISTENER_H
#define CHAT_LISTENER_H

#include <stdint.h>
#include "chat_protocol.h"
#include "chat_utils.h"
#include <pthread.h>

typedef struct {
    client_connection_t* conn;
    uint8_t room_key[ROOM_KEY_SIZE];
    int running;
    pthread_mutex_t lock;
} chat_listener_args_t;

void* chat_listener_thread(void* arg);

#endif // CHAT_LISTENER_H
