#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "jwt.h"
#include "database.h"
#include "location_handler.h"
#include "logger.h"
#include "jwt_manager.h"

// INSERT_LOCATION
char* handle_insert_location(const cJSON* request_json) {
    location_t loc;
    memset(&loc, 0, sizeof(loc));
    const cJSON *latitude_item = cJSON_GetObjectItem(request_json, "latitude");
    const cJSON *longitude_item = cJSON_GetObjectItem(request_json, "longitude");
    const cJSON *timestamp_item = cJSON_GetObjectItem(request_json, "timestamp");
    const cJSON *jwt_item = cJSON_GetObjectItem(request_json, "jwt");
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "insert_location_response");
    
    // JWT'den user_id çek
    jwt_t *jwt = NULL;
    int decode_result = jwt_decode(&jwt, jwt_item->valuestring, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    int user_id = -1;
    if (decode_result == 0 && jwt) {
        const char* sub_str = jwt_get_grant(jwt, "sub");
        if (sub_str) {
            user_id = atoi(sub_str);
        }
        jwt_free(jwt);
    }
    if (user_id < 0) {
        cJSON_AddBoolToObject(resp, "success", 0);
        cJSON_AddStringToObject(resp, "error", "Invalid or missing user_id in JWT");
        char* resp_str = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return resp_str;
    }
    loc.user_id = user_id;
    loc.latitude = latitude_item->valuedouble;
    loc.longitude = longitude_item->valuedouble;
    loc.timestamp = timestamp_item->valuedouble;

    printf("DEBUG: Inserting location: user_id=%d, latitude=%.8f, longitude=%.8f, timestamp=%ld\n",
           loc.user_id, loc.latitude, loc.longitude, loc.timestamp);

    int result = db_insert_location(&loc);
    cJSON_AddBoolToObject(resp, "success", result > 0);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}

// SELECT_LOCATION_OF_USER
char* handle_select_location_of_user(const cJSON* request_json) {
    const cJSON *jwt_item = cJSON_GetObjectItem(request_json, "jwt");
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "select_location_of_user_response");    

    // JWT'den user_id çek
    jwt_t *jwt = NULL;
    int decode_result = jwt_decode(&jwt, jwt_item->valuestring, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    int user_id = -1;
    if (decode_result == 0 && jwt) {
        const char* sub_str = jwt_get_grant(jwt, "sub");
        if (sub_str) {
            user_id = atoi(sub_str);
        }
        jwt_free(jwt);
    }
    if (user_id < 0) {
        cJSON_AddBoolToObject(resp, "success", 0);
        cJSON_AddStringToObject(resp, "error", "Invalid or missing user_id in JWT");
        char* resp_str = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return resp_str;
    }

    double lat = 0, lng = 0;
    int found = db_select_location_of_user(user_id, &lat, &lng);
    
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
    const cJSON *jwt_item = cJSON_GetObjectItem(request_json, "jwt");

    int unit_id = cJSON_GetObjectItem(request_json, "unit_id")->valueint;
    location_t* locations = NULL;

    // JWT'den user_id çek
    jwt_t *jwt = NULL;
    jwt_decode(&jwt, jwt_item->valuestring, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));

    int user_unit_id = jwt_get_unit_id(jwt_item->valuestring);
    int user_privilege = get_jwt_privilege(jwt_item->valuestring);

    if (user_unit_id != unit_id && user_privilege != ADMIN_PRIVILEGE) {
        cJSON* resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "action", "select_latest_locations_by_unit_response");
        cJSON_AddBoolToObject(resp, "success", 0);
        cJSON_AddStringToObject(resp, "error", "Unauthorized access to unit locations");
        char* resp_str = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return resp_str;
    }
    
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
        free(locations);
    }
    cJSON_AddItemToObject(resp, "locations", arr);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}

// SELECT_LATEST_LOCATIONS_OF_MY_UNIT
char* handle_select_latest_locations_of_my_unit(const cJSON* request_json) {
    const cJSON *jwt_item = cJSON_GetObjectItem(request_json, "jwt");

    location_t* locations = NULL;

    // JWT'den user_id çek
    jwt_t *jwt = NULL;
    jwt_decode(&jwt, jwt_item->valuestring, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));

    int user_unit_id = jwt_get_unit_id(jwt_item->valuestring);

    int count = 0;
    int found = db_select_latest_locations_by_unit(user_unit_id, &locations, &count);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "select_latest_locations_of_my_unit_response");
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
        free(locations);
    }
    cJSON_AddItemToObject(resp, "locations", arr);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}

// SELECT_LATEST_LOCATIONS_ALL_USERS
char* handle_select_latest_locations_all_users(const cJSON* request_json) {
    const cJSON *jwt_item = cJSON_GetObjectItem(request_json, "jwt");

    // JWT'den user_id çek
    jwt_t *jwt = NULL;
    jwt_decode(&jwt, jwt_item->valuestring, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));

    int user_privilege = get_jwt_privilege(jwt_item->valuestring);

    if (user_privilege != ADMIN_PRIVILEGE) {
        cJSON* resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "action", "select_latest_locations_all_users_response");
        cJSON_AddBoolToObject(resp, "success", 0);
        cJSON_AddStringToObject(resp, "error", "Unauthorized access to all locations");
        char* resp_str = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return resp_str;
    }

    (void)request_json;
    location_t* locations = NULL;
    int count = 0;
    int found = db_select_latest_locations_all_users(&locations, &count);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "select_latest_locations_all_users_response");
    cJSON_AddBoolToObject(resp, "success", found > 0);
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
        free(locations);
    }
    cJSON_AddItemToObject(resp, "locations", arr);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}

// SELECT_LATEST_LOCATIONS_ALL_USERS_BY_RADIUS
char* handle_select_latest_locations_all_users_by_radius(const cJSON* request_json) {
    const cJSON *jwt_item = cJSON_GetObjectItem(request_json, "jwt");

    // JWT'den user_id çek
    jwt_t *jwt = NULL;
    jwt_decode(&jwt, jwt_item->valuestring, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));

    if (verify_jwt(jwt_item->valuestring) != 0) {
        cJSON* resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "action", "select_latest_locations_all_users_by_radius_response");
        cJSON_AddBoolToObject(resp, "success", 0);
        cJSON_AddStringToObject(resp, "error", "Invalid JWT");
        char* resp_str = cJSON_PrintUnformatted(resp);
        cJSON_Delete(resp);
        return resp_str;
    }

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
        free(locations);
    }
    cJSON_AddItemToObject(resp, "locations", arr);
    char* resp_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    return resp_str;
}
