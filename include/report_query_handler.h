#ifndef REPORT_QUERY_HANDLER_H
#define REPORT_QUERY_HANDLER_H

#include <stddef.h>

// JWT token ile rapor sorgulama, JSON stringi out_json'a yazar
int handle_report_query(const char* jwt_token, char* out_json, size_t out_json_size);

#endif // REPORT_QUERY_HANDLER_H
