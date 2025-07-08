#ifndef LOCATION_MANAGER_H
#define LOCATION_MANAGER_H

#include "encrypted_client.h"
#include "database.h"

void send_insert_location(client_connection_t* conn, const location_t* location, const char* jwt_token);
void send_select_location_of_user(client_connection_t* conn, const char* jwt_token);
void send_select_latest_locations_by_unit(client_connection_t* conn, int unit_id, const char* jwt_token);
void send_select_latest_locations_all_users(client_connection_t* conn, const char* jwt_token);
void send_select_latest_locations_all_users_by_radius(client_connection_t* conn, double latitude, double longitude, double radius, const char* jwt_token);
#endif // LOCATION_MANAGER_H