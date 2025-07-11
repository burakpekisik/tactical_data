#ifndef REPORT_QUERY_MANAGER_H
#define REPORT_QUERY_MANAGER_H

#include "encrypted_client.h"

void query_my_replies_with_jwt(client_connection_t* conn, const char* jwt_token);
void query_my_replies(client_connection_t* conn, const char* jwt_token);
void query_replies_to_one_report(client_connection_t* conn, const char* jwt_token);

#endif /* REPORT_QUERY_MANAGER_H */