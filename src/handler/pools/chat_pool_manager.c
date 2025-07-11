#include "handle_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "queue_manager.h"
#include "pool_manager.h"
#include "chat_handler.h"
#include "thread_monitor.h"
#include "logger.h"

thread_pool_t chat_create_room_pool;
thread_pool_t chat_list_rooms_pool;
thread_pool_t chat_join_room_pool;
thread_pool_t chat_get_messages_pool;
thread_pool_t chat_send_message_pool;
thread_pool_t chat_leave_room_pool;

// Her fonksiyon için wrapper (örnek: chat_create_room)
void chat_create_room_task(void* arg) {
    struct { char* decrypted_json; const char* jwt_token; pool_result_t* result; const uint8_t* session_key; } 
    *params = arg;
    PRINTF_LOG("[DEBUG][chat_create_room_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][chat_create_room_task] arg is NULL!\n");
        return;
    }
    pthread_t tid = pthread_self();
    // Duplicate kontrolü
    if (is_duplicate_task(-1, "chat_create_room_task")) {
        PRINTF_LOG("[DUPLICATE] chat_create_room_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, -1, "N/A", 0, "chat_create_room_task");
    PRINTF_LOG("[DEBUG][chat_create_room_task] malloc params=%p, decrypted_json=%p\n", params, params ? params->decrypted_json : NULL);
    char* r = handle_chat_create_room(params->decrypted_json, params->jwt_token);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(r, params->session_key, "chat_create_room");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    if (r) free(r);
    if (params->decrypted_json) free(params->decrypted_json);
    PRINTF_LOG("[DEBUG][chat_create_room_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}
void chat_list_rooms_task(void* arg) {
    struct { char* decrypted_json; const char* jwt_token; pool_result_t* result; const uint8_t* session_key; } 
    *params = arg;
    PRINTF_LOG("[DEBUG][chat_list_rooms_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][chat_list_rooms_task] arg is NULL!\n");
        return;
    }
    pthread_t tid = pthread_self();
    if (is_duplicate_task(-1, "chat_list_rooms_task")) {
        PRINTF_LOG("[DUPLICATE] chat_list_rooms_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, -1, "N/A", 0, "chat_list_rooms_task");
    PRINTF_LOG("[DEBUG][chat_list_rooms_task] malloc params=%p, decrypted_json=%p\n", params, params ? params->decrypted_json : NULL);
    char* r = handle_chat_list_rooms(params->decrypted_json, params->jwt_token);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(r, params->session_key, "chat_list_rooms");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    if (r) free(r);
    if (params->decrypted_json) free(params->decrypted_json);
    PRINTF_LOG("[DEBUG][chat_list_rooms_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}
void chat_join_room_task(void* arg) {
    struct { char* decrypted_json; const char* jwt_token; int client_socket; pool_result_t* result; const uint8_t* session_key; } *params = arg;
    PRINTF_LOG("[DEBUG][chat_join_room_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][chat_join_room_task] arg is NULL!\n");
        return;
    }
    pthread_t tid = pthread_self();
    if (is_duplicate_task(params->client_socket, "chat_join_room_task")) {
        PRINTF_LOG("[DUPLICATE] chat_join_room_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, params->client_socket, "N/A", 0, "chat_join_room_task");
    PRINTF_LOG("[DEBUG][chat_join_room_task] malloc params=%p, decrypted_json=%p\n", params, params ? params->decrypted_json : NULL);
    char* r = handle_chat_join_room(params->decrypted_json, params->jwt_token, params->client_socket);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(r, params->session_key, "chat_join_room");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    if (r) free(r);
    if (params->decrypted_json) free(params->decrypted_json);
    PRINTF_LOG("[DEBUG][chat_join_room_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}
void chat_get_messages_task(void* arg) {
    struct { char* decrypted_json; pool_result_t* result; const uint8_t* session_key; } *params = arg;
    PRINTF_LOG("[DEBUG][chat_get_messages_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][chat_get_messages_task] arg is NULL!\n");
        return;
    }
    pthread_t tid = pthread_self();
    if (is_duplicate_task(-1, "chat_get_messages_task")) {
        PRINTF_LOG("[DUPLICATE] chat_get_messages_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, -1, "N/A", 0, "chat_get_messages_task");
    PRINTF_LOG("[DEBUG][chat_get_messages_task] malloc params=%p, decrypted_json=%p\n", params, params ? params->decrypted_json : NULL);
    char* r = handle_chat_get_messages(params->decrypted_json);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(r, params->session_key, "chat_get_messages");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    if (r) free(r);
    if (params->decrypted_json) free(params->decrypted_json);
    PRINTF_LOG("[DEBUG][chat_get_messages_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}
void chat_send_message_task(void* arg) {
    struct { char* decrypted_json; const char* jwt_token; int client_socket; pool_result_t* result; const uint8_t* session_key; } *params = arg;
    PRINTF_LOG("[DEBUG][chat_send_message_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][chat_send_message_task] arg is NULL!\n");
        return;
    }
    pthread_t tid = pthread_self();
    if (is_duplicate_task(params->client_socket, "chat_send_message_task")) {
        PRINTF_LOG("[DUPLICATE] chat_send_message_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, params->client_socket, "N/A", 0, "chat_send_message_task");
    PRINTF_LOG("[DEBUG][chat_send_message_task] malloc params=%p, decrypted_json=%p\n", params, params ? params->decrypted_json : NULL);
    char* r = handle_chat_send_message(params->decrypted_json, params->jwt_token, params->client_socket);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(r, params->session_key, "chat_send_message");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    if (r) free(r);
    if (params->decrypted_json) free(params->decrypted_json);
    PRINTF_LOG("[DEBUG][chat_send_message_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}
void chat_leave_room_task(void* arg) {
    struct { char* decrypted_json; int client_socket; pool_result_t* result; const uint8_t* session_key; } *params = arg;
    PRINTF_LOG("[DEBUG][chat_leave_room_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][chat_leave_room_task] arg is NULL!\n");
        return;
    }
    pthread_t tid = pthread_self();
    if (is_duplicate_task(params->client_socket, "chat_leave_room_task")) {
        PRINTF_LOG("[DUPLICATE] chat_leave_room_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, params->client_socket, "N/A", 0, "chat_leave_room_task");
    PRINTF_LOG("[DEBUG][chat_leave_room_task] malloc params=%p, decrypted_json=%p\n", params, params ? params->decrypted_json : NULL);
    char* r = handle_chat_leave_room(params->decrypted_json, params->client_socket);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(r, params->session_key, "chat_leave_room");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    if (r) free(r);
    if (params->decrypted_json) free(params->decrypted_json);
    PRINTF_LOG("[DEBUG][chat_leave_room_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}

// Thread pool init fonksiyonu (main'de çağrılmalı)
void init_chat_pools() {
    thread_pool_init(&chat_create_room_pool, 2, 32);
    thread_pool_init(&chat_list_rooms_pool, 2, 32);
    thread_pool_init(&chat_join_room_pool, 2, 32);
    thread_pool_init(&chat_get_messages_pool, 2, 32);
    thread_pool_init(&chat_send_message_pool, 2, 32);
    thread_pool_init(&chat_leave_room_pool, 2, 32);
}