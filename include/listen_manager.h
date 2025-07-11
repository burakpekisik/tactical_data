#ifndef LISTEN_MANAGER_H
#define LISTEN_MANAGER_H

#include "encrypted_client.h"

void listen_report_replies(client_connection_t* conn);
void listen_for_admin_notifications(client_connection_t* conn);

#endif // LISTEN_MANAGER_H