#ifndef ADMIN_REPLY_MANAGER_H
#define ADMIN_REPLY_MANAGER_H

#include <stdbool.h>
#include "encrypted_client.h"

typedef struct {
    int user_id;
    int user_socket;
} user_socket_map_t;

// Kullanıcı login olduğunda çağrılır
void admin_reply_manager_register_user(int user_id, int user_socket);
// Kullanıcı bağlantısı kopunca çağrılır
void admin_reply_manager_remove_user(int user_socket);
// Admin reply: report_id'den user_id'yi bulup, aktifse mesajı iletir
bool admin_reply_manager_send_reply(int report_id, const char* message, int admin_socket);
// Admin reply fonksiyonu: terminalden rapor ID ve mesaj alır, şifreler ve gönderir
int admin_reply_to_report(client_connection_t* conn, const char* jwt_token);
void handle_reply_report(const char* decrypted_json, const char* jwt_token, int client_socket, char* out, size_t out_size);

#endif // ADMIN_REPLY_MANAGER_H
