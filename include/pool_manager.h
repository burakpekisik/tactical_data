#ifndef POOL_MANAGER_H
#define POOL_MANAGER_H

#include <pthread.h>
#include "queue_manager.h"

extern thread_pool_t chat_create_room_pool;
extern thread_pool_t chat_list_rooms_pool;
extern thread_pool_t chat_join_room_pool;
extern thread_pool_t chat_get_messages_pool;
extern thread_pool_t chat_send_message_pool;
extern thread_pool_t chat_leave_room_pool;

extern thread_pool_t report_query_pool;
extern thread_pool_t reply_query_pool;
extern thread_pool_t query_my_replies_pool;
extern thread_pool_t query_replies_one_report_pool;
extern thread_pool_t reply_watch_pool;


// Sonuç beklemek için yapı
typedef struct {
    char* result;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int ready;
} pool_result_t;

void chat_create_room_task(void* arg);
void chat_list_rooms_task(void* arg);
void chat_join_room_task(void* arg);
void chat_get_messages_task(void* arg);
void chat_send_message_task(void* arg);
void chat_leave_room_task(void* arg);
void init_chat_pools();

void report_query_task(void* arg);
void reply_query_task(void* arg);
void query_my_replies_task(void* arg);
void query_replies_one_report_task(void* arg);
void init_query_pools();

void reply_watch_task(void* arg);
void init_reply_watch_pool();

#endif // POOL_MANAGER_H