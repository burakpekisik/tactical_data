#ifndef INFO_MANAGER_H
#define INFO_MANAGER_H

#include "encrypted_client.h"

int send_info_message(client_connection_t* conn, const char* jwt_token);

#endif // INFO_MANAGER_H