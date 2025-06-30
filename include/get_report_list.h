#ifndef GET_REPORT_LIST_H
#define GET_REPORT_LIST_H

#include "encrypted_client.h"

int get_report_list_by_user(client_connection_t* conn, const char* jwt_token);

#endif // GET_REPORT_LIST_H