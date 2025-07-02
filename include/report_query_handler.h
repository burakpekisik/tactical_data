#ifndef REPORT_QUERY_HANDLER_H
#define REPORT_QUERY_HANDLER_H

#include <stddef.h>

// JWT token ile rapor sorgulama, JSON stringi out_json'a yazar
int handle_report_query(const char* jwt_token, char* out_json, size_t out_json_size);

// JWT token ile reply sorgulama, JSON stringi out_json'a yazar
int handle_reply_query(const char* jwt_token, char* out_json, size_t out_json_size);

// JWT token ile kullanıcının raporlarına gelen reply'ları sorgulama
int handle_query_my_replies(const char* jwt_token, char* out_json, size_t out_json_size);

#endif // REPORT_QUERY_HANDLER_H
