#ifndef BROADCAST_MANAGER_H
#define BROADCAST_MANAGER_H

void add_socket_to_room(int room_id, int client_socket);
void broadcast_message_to_room(int room_id, const char* plain_json, int exclude_socket);

#endif