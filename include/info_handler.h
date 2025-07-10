#ifndef INFO_HANDLER_H
#define INFO_HANDLER_H

#include "encrypted_client.h"

int handle_info_request(const char* jwt_token, char* out_buf, size_t out_buf_size);

#endif // INFO_HANDLER_H