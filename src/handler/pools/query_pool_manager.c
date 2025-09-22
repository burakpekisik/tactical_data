#include "pool_manager.h"
#include "handle_manager.h"
#include "thread_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "queue_manager.h"
#include "report_query_handler.h"
#include "admin_reply_manager.h"
#include "large_response.h"
#include "logger.h"

thread_pool_t report_query_pool;
thread_pool_t reply_query_pool;
thread_pool_t query_my_replies_pool;
thread_pool_t query_replies_one_report_pool;

void report_query_task(void* arg) {
    struct { char* jwt_token; char* plain_result; size_t result_size; pool_result_t* result; const uint8_t* session_key; int client_socket; } *params = arg;
    pthread_t tid = pthread_self();
    if (is_duplicate_task(params->client_socket, "report_query_task")) {
        PRINTF_LOG("[DUPLICATE] report_query_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, params->client_socket, "N/A", 0, "report_query_task");
    PRINTF_LOG("[DEBUG][report_query_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][report_query_task] arg is NULL!\n");
        return;
    }
    handle_report_query(params->jwt_token, params->plain_result, params->result_size);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(params->plain_result, params->session_key, "REPORT_QUERY");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    PRINTF_LOG("[DEBUG][report_query_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}

void reply_query_task(void* arg) {
    struct { char* jwt_token; char* plain_result; size_t result_size; pool_result_t* result; const uint8_t* session_key; int client_socket; } *params = arg;
    pthread_t tid = pthread_self();
    if (is_duplicate_task(params->client_socket, "reply_query_task")) {
        PRINTF_LOG("[DUPLICATE] reply_query_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, params->client_socket, "N/A", 0, "reply_query_task");
    PRINTF_LOG("[DEBUG][reply_query_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][reply_query_task] arg is NULL!\n");
        return;
    }
    handle_reply_query(params->jwt_token, params->plain_result, params->result_size);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(params->plain_result, params->session_key, "REPLY_QUERY");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    PRINTF_LOG("[DEBUG][reply_query_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}

void query_my_replies_task(void* arg) {
    struct { char* jwt_token; char* plain_result; size_t result_size; pool_result_t* result; const uint8_t* session_key; int client_socket; } *params = arg;
    pthread_t tid = pthread_self();
    if (is_duplicate_task(params->client_socket, "query_my_replies_task")) {
        PRINTF_LOG("[DUPLICATE] query_my_replies_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, params->client_socket, "N/A", 0, "query_my_replies_task");
    PRINTF_LOG("[DEBUG][query_my_replies_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][query_my_replies_task] arg is NULL!\n");
        return;
    }
    handle_query_my_replies(params->jwt_token, params->plain_result, params->result_size);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(params->plain_result, params->session_key, "QUERY_MY_REPLIES");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    PRINTF_LOG("[DEBUG][query_my_replies_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}

void query_replies_one_report_task(void* arg) {
    struct { char* jwt_token; cJSON* root; char* plain_result; size_t result_size; pool_result_t* result; const uint8_t* session_key; int client_socket; } *params = arg;
    pthread_t tid = pthread_self();
    if (is_duplicate_task(params->client_socket, "query_replies_one_report_task")) {
        PRINTF_LOG("[DUPLICATE] query_replies_one_report_task already running for this client. Skipping.\n");
        if (params) free(params);
        return;
    }
    add_thread_info(tid, params->client_socket, "N/A", 0, "query_replies_one_report_task");
    PRINTF_LOG("[DEBUG][query_replies_one_report_task] ENTRY arg=%p\n", arg);
    if (!arg) {
        PRINTF_LOG("[ERROR][query_replies_one_report_task] arg is NULL!\n");
        return;
    }
    handle_query_replies_to_one_report(params->jwt_token, params->root, params->plain_result, params->result_size);
    pthread_mutex_lock(&params->result->mutex);
    params->result->result = encrypt_and_format_response(params->plain_result, params->session_key, "QUERY_REPLIES_ONE_REPORT");
    params->result->ready = 1;
    pthread_cond_signal(&params->result->cond);
    pthread_mutex_unlock(&params->result->mutex);
    PRINTF_LOG("[DEBUG][query_replies_one_report_task] free params=%p\n", params);
    if (params) free(params);
    remove_thread_info(pthread_self());
}

void init_query_pools() {
    thread_pool_init(&report_query_pool, 4, 32);
    thread_pool_init(&reply_query_pool, 4, 32);
    thread_pool_init(&query_my_replies_pool, 4, 32);
    thread_pool_init(&query_replies_one_report_pool, 4, 32);
}
