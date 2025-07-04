#include "chat_listener.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "logger.h"
#include "protocol_parser.h"

void* chat_listener_thread(void* arg) {
    char* command = NULL;
    char* filename = NULL;
    char* hexdata = NULL;
    char* jwt_token = NULL; 
    char* display = NULL;
    char* decrypted = NULL;
    char* response = NULL;

    chat_listener_args_t* args = (chat_listener_args_t*)arg;
    printf("[LISTENER] Thread started!\n");
    // Print args
    printf("[LISTENER] args->conn: %p\n", (void*)args->conn);
    printf("[LISTENER] args->running: %d\n", args->running);
    printf("[LISTENER] args->room_key: ");
    for (int i = 0; i < ROOM_KEY_SIZE; i++) {
        printf("%02x", args->room_key[i]);
    }
    printf("\n");
    while (1) {
        pthread_mutex_lock(&args->lock);
        int running = args->running;
        pthread_mutex_unlock(&args->lock);
        if (!running) break;
        response = receive_encrypted_response_room_key(args->conn, args->room_key);
        printf("[LISTENER] Received response: %s\n", response ? response : "(null)");
        if (!response) continue;
        if (strncmp(response, "ENCRYPTED:", 10) == 0) {
            printf("[LISTENER] Received ENCRYPTED message: %.60s...\n", response);
            command = NULL;
            filename = NULL;
            hexdata = NULL;
            jwt_token = NULL;
            if (parse_encrypted_protocol_message(response, &command, &filename, &hexdata, &jwt_token) == 0) {
                if (command && (strcmp(command, "chat_send_message") == 0 || strcmp(command, "chat_receive_message") == 0)) {
                    printf("[LISTENER] Action: %s, decrypting...\n", command);
                    decrypted = NULL;
                    if (decrypt_chat_message(hexdata, strlen(hexdata), args->room_key, &decrypted) == 0 && decrypted) {
                        printf("[LISTENER] Decrypted JSON: %s\n", decrypted);
                        cJSON* msg_json = cJSON_Parse(decrypted);
                        if (msg_json) {
                            cJSON* sender = cJSON_GetObjectItem(msg_json, "sender_name");
                            cJSON* message = cJSON_GetObjectItem(msg_json, "message");
                            cJSON* ts = cJSON_GetObjectItem(msg_json, "timestamp");
                            if (cJSON_IsString(sender) && cJSON_IsString(message) && cJSON_IsNumber(ts)) {
                                display = format_chat_message_display(sender->valuestring, message->valuestring, (time_t)ts->valuedouble);
                                if (display) {
                                    printf("[LISTENER] Displaying chat message: %s\n", display);
                                    printf("\n%s\n> ", display);
                                    fflush(stdout);
                                    free(display);
                                }
                            }
                            cJSON_Delete(msg_json);
                        }
                        free(decrypted);
                    } else {
                        printf("[LISTENER][ERROR] Decryption failed!\n");
                    }
                }
                if (command) free(command);
                if (filename) free(filename);
                if (hexdata) free(hexdata);
                if (jwt_token) free(jwt_token);
            }
        }
        free(response);
    }
    return NULL;
}
