#ifndef ADMIN_REPLY_MANAGER_H
#define ADMIN_REPLY_MANAGER_H

#include <stdbool.h>

// Kullanıcı login olduğunda çağrılır
void admin_reply_manager_register_user(int user_id, int user_socket);
// Kullanıcı bağlantısı kopunca çağrılır
void admin_reply_manager_remove_user(int user_socket);
// Admin reply: report_id'den user_id'yi bulup, aktifse mesajı iletir
bool admin_reply_manager_send_reply(int report_id, const char* message, int admin_socket);

#endif // ADMIN_REPLY_MANAGER_H
