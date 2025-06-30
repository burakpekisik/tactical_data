#ifndef ADMIN_NOTIFY_MANAGER_H
#define ADMIN_NOTIFY_MANAGER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int socket_fd;
    int privilege; // 1: admin, 0: normal user
    char username[64];
} connected_client_t;

void admin_notify_manager_init(void);
void admin_notify_manager_add_client(int socket_fd, int privilege, const char* username);
void admin_notify_manager_remove_client(int socket_fd);
void admin_notify_manager_notify_admins(const char* report_json, int sender_socket, int sender_privilege);
void admin_notify_manager_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // ADMIN_NOTIFY_MANAGER_H
