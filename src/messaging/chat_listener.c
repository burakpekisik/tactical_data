#include "chat_listener.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "logger.h"
#include "protocol_parser.h"

void* chat_listener_thread(void* arg) {
    char* display = NULL;
    char* response = NULL;

    chat_listener_args_t* args = (chat_listener_args_t*)arg;
    while (1) {
        pthread_mutex_lock(&args->lock);
        int running = args->running;
        pthread_mutex_unlock(&args->lock);
        if (!running) break;
        response = receive_encrypted_response_room_key(args->conn, args->room_key);
        if (!response) continue;
        // printf("[LISTENER] Received response: %s\n", response ? response : "(null)");
        // if (strncmp(response, "ENCRYPTED:", 10) == 0) {
        // printf("[LISTENER] Received ENCRYPTED message: %.60s...\n", response);
        cJSON* msg_json = cJSON_Parse(response);
        if (msg_json) {
            cJSON* sender = cJSON_GetObjectItem(msg_json, "sender_name");
            cJSON* message = cJSON_GetObjectItem(msg_json, "message");
            cJSON* ts = cJSON_GetObjectItem(msg_json, "timestamp");
            if (cJSON_IsString(sender) && cJSON_IsString(message) && cJSON_IsNumber(ts)) {
                display = format_chat_message_display(sender->valuestring, message->valuestring, (time_t)ts->valuedouble);
                if (display) {
                    printf("\n%s\n> ", display);
                    fflush(stdout);
                    free(display);
                }
            }
            cJSON_Delete(msg_json);
        }
        // }
        free(response);
    }
    return NULL;
}
