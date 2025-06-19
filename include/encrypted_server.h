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
char* handle_encrypted_request(const char* filename, const char* encrypted_content, const uint8_t* session_key);
void* queue_processor(void* arg);
void handle_signal(int sig);

#endif /* ENCRYPTED_SERVER_H */