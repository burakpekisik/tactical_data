#ifndef LOCATION_HANDLER_H
#define LOCATION_HANDLER_H

char* handle_insert_location(const cJSON* request_json);
char* handle_select_location_of_user(const cJSON* request_json);
char* handle_select_latest_locations_by_unit(const cJSON* request_json);
char* handle_select_latest_locations_all_users(const cJSON* request_json);
char* handle_select_latest_locations_all_users_by_radius(const cJSON* request_json);
char* handle_select_latest_locations_of_my_unit(const cJSON* request_json);

#endif // LOCATION_HANDLER_H