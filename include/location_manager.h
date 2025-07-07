#ifndef LOCATION_MANAGER_H
#define LOCATION_MANAGER_H

#include "encrypted_client.h"
#include "database.h"

int protocol_insert_location(client_connection_t* conn, const location_t* location, char** response_out);
int protocol_select_location_of_user(client_connection_t* conn, int user_id, char** response_out);
int protocol_select_latest_locations_by_unit(client_connection_t* conn, int unit_id, char** response_out);
int protocol_select_latest_locations_all_users(client_connection_t* conn, char** response_out);
int protocol_select_latest_locations_all_users_by_radius(client_connection_t* conn, double latitude, double longitude, double radius, char** response_out);

#endif // LOCATION_MANAGER_H