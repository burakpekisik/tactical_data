#ifndef CHAT_HANDLER_H
#define CHAT_HANDLER_H

char* handle_chat_get_messages(const char* decrypted_json);
char* handle_chat_leave_room(const char* decrypted_json, int client_socket);
char* handle_chat_send_message(const char* decrypted_json, const char* jwt_token, int client_socket);

char* handle_chat_join_room(const char* decrypted_json, const char* jwt_token, int client_socket);
char* handle_chat_list_rooms(const char* decrypted_json, const char* jwt_token);
char* handle_chat_create_room(const char* decrypted_json, const char* jwt_token);


#endif // CHAT_HANDLER_H