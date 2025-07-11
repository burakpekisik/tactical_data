#ifndef INFO_MANAGER_H
#define INFO_MANAGER_H

#include "encrypted_client.h"

char* send_info_message(client_connection_t* conn, const char* jwt_token);
int send_info_message_qt(const char* encrypted_response, const uint8_t* aes_key, char** out_buf, size_t out_buf_size);
    
#endif // INFO_MANAGER_H