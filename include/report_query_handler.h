#ifndef REPORT_QUERY_HANDLER_H
#define REPORT_QUERY_HANDLER_H

#include <stddef.h>
#include <cjson/cJSON.h>

// JWT token ile rapor sorgulama, JSON stringi out_json'a yazar
int handle_report_query(const char* jwt_token, char* out_json, size_t out_json_size);

// JWT token ile reply sorgulama, JSON stringi out_json'a yazar
int handle_reply_query(const char* jwt_token, char* out_json, size_t out_json_size);

int handle_query_my_replies(const char* jwt_token, char* out_json, size_t out_json_size);

int handle_query_replies_to_one_report(const char* jwt_token, cJSON* root, char* out_json, size_t out_json_size);

#endif // REPORT_QUERY_HANDLER_H
