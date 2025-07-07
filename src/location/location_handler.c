#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "database.h"
#include "location_handler.h"

// INSERT_LOCATION
char* handle_insert_location(const cJSON* request_json) {
    location_t loc;
    memset(&loc, 0, sizeof(loc));
    loc.user_id = cJSON_GetObjectItem(request_json, "user_id")->valueint;
    loc.latitude = cJSON_GetObjectItem(request_json, "latitude")->valuedouble;
    loc.longitude = cJSON_GetObjectItem(request_json, "longitude")->valuedouble;
    loc.timestamp = cJSON_GetObjectItem(request_json, "timestamp")->valuedouble;
    int result = db_insert_location(&loc);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "insert_location_response");
    cJSON_AddBoolToObject(resp, "success", result == 0);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}

// SELECT_LOCATION_OF_USER
char* handle_select_location_of_user(const cJSON* request_json) {
    int user_id = cJSON_GetObjectItem(request_json, "user_id")->valueint;
    double lat = 0, lng = 0;
    int found = db_select_location_of_user(user_id, &lat, &lng);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "select_location_of_user_response");
    cJSON_AddBoolToObject(resp, "success", found == 0);
    if (found == 0) {
        cJSON_AddNumberToObject(resp, "latitude", lat);
        cJSON_AddNumberToObject(resp, "longitude", lng);
    }
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}

// SELECT_LATEST_LOCATIONS_BY_UNIT
char* handle_select_latest_locations_by_unit(const cJSON* request_json) {
    int unit_id = cJSON_GetObjectItem(request_json, "unit_id")->valueint;
    location_t* locations = NULL;
    int count = 0;
    int found = db_select_latest_locations_by_unit(unit_id, &locations, &count);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "select_latest_locations_by_unit_response");
    cJSON_AddBoolToObject(resp, "success", found == 0);
    cJSON* arr = cJSON_CreateArray();
    if (found == 0 && locations) {
        for (int i = 0; i < count; i++) {
            cJSON* item = cJSON_CreateObject();
            cJSON_AddNumberToObject(item, "user_id", locations[i].user_id);
            cJSON_AddNumberToObject(item, "latitude", locations[i].latitude);
            cJSON_AddNumberToObject(item, "longitude", locations[i].longitude);
            cJSON_AddNumberToObject(item, "timestamp", locations[i].timestamp);
            cJSON_AddItemToArray(arr, item);
        }
        db_free(locations);
    }
    cJSON_AddItemToObject(resp, "locations", arr);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}

// SELECT_LATEST_LOCATIONS_ALL_USERS
char* handle_select_latest_locations_all_users(const cJSON* request_json) {
    (void)request_json;
    location_t* locations = NULL;
    int count = 0;
    int found = db_select_latest_locations_all_users(&locations, &count);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "select_latest_locations_all_users_response");
    cJSON_AddBoolToObject(resp, "success", found == 0);
    cJSON* arr = cJSON_CreateArray();
    if (found == 0 && locations) {
        for (int i = 0; i < count; i++) {
            cJSON* item = cJSON_CreateObject();
            cJSON_AddNumberToObject(item, "user_id", locations[i].user_id);
            cJSON_AddNumberToObject(item, "latitude", locations[i].latitude);
            cJSON_AddNumberToObject(item, "longitude", locations[i].longitude);
            cJSON_AddNumberToObject(item, "timestamp", locations[i].timestamp);
            cJSON_AddItemToArray(arr, item);
        }
        db_free(locations);
    }
    cJSON_AddItemToObject(resp, "locations", arr);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}

// SELECT_LATEST_LOCATIONS_ALL_USERS_BY_RADIUS
char* handle_select_latest_locations_all_users_by_radius(const cJSON* request_json) {
    double lat = cJSON_GetObjectItem(request_json, "latitude")->valuedouble;
    double lng = cJSON_GetObjectItem(request_json, "longitude")->valuedouble;
    double radius = cJSON_GetObjectItem(request_json, "radius")->valuedouble;
    location_t* locations = NULL;
    int count = 0;
    int found = db_select_latest_locations_all_users_by_radius(lat, lng, radius, &locations, &count);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "select_latest_locations_all_users_by_radius_response");
    cJSON_AddBoolToObject(resp, "success", found == 0);
    cJSON* arr = cJSON_CreateArray();
    if (found == 0 && locations) {
        for (int i = 0; i < count; i++) {
            cJSON* item = cJSON_CreateObject();
            cJSON_AddNumberToObject(item, "user_id", locations[i].user_id);
            cJSON_AddNumberToObject(item, "latitude", locations[i].latitude);
            cJSON_AddNumberToObject(item, "longitude", locations[i].longitude);
            cJSON_AddNumberToObject(item, "timestamp", locations[i].timestamp);
            cJSON_AddItemToArray(arr, item);
        }
        db_free(locations);
    }
    cJSON_AddItemToObject(resp, "locations", arr);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}
