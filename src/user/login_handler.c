#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <jwt.h>
#include "config.h"
#include "login_user.h"
#include "thread_monitor.h"
#include "admin_reply_manager.h"
#include "admin_notify_manager.h"
#include "database.h"
#include <sys/socket.h>
#include <unistd.h>


// LOGIN isteği handler'ı
void handle_login_request(const char* buffer, int client_socket, pthread_t current_thread) {
    char username[128] = "", password[128] = "";
    sscanf(buffer + 6, "%127[^:]:%127s", username, password);
    char* jwt = login_user_with_argon2(username, password);
    if (jwt) {
        char response[2048];
        snprintf(response, sizeof(response), "JWT:%s", jwt);
        send(client_socket, response, strlen(response), 0);
        // JWT'den privilege ve user_id çek
        int privilege = 0;
        int user_id = -1;
        jwt_t *jwt_ptr = NULL;
        if (jwt_decode(&jwt_ptr, jwt, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) == 0 && jwt_ptr) {
            privilege = jwt_get_grant_int(jwt_ptr, "privilege");
            const char* sub = jwt_get_grant(jwt_ptr, "sub");
            if (sub) user_id = atoi(sub);
            jwt_free(jwt_ptr);
        }
        admin_notify_manager_add_client(client_socket, privilege, username);
        if (user_id > 0) {
            admin_reply_manager_register_user(user_id, client_socket);
        }
        free(jwt);
    } else {
        char* fail = "FAIL";
        send(client_socket, fail, strlen(fail), 0);
    }
    close(client_socket);
    remove_thread_info(current_thread);
}