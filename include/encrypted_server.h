#ifndef ENCRYPTED_SERVER_H
#define ENCRYPTED_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include "config.h"
#include "connection_manager.h"

// Function prototypes
int parse_protocol_message(const char* message, char** command, char** filename, char** content);
void* handle_client(void* arg);
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key, const char* jwt_token);
void* queue_processor(void* arg);
void handle_signal(int sig);
void* periodic_backup_thread();
int parse_encrypted_protocol_message(const char* message, char** command, char** filename, char** hex_data, char** jwt_token);

#endif /* ENCRYPTED_SERVER_H */