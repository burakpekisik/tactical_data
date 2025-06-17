#ifndef _JSON_UTILS_H_
#define _JSON_UTILS_H_

#include <cjson/cJSON.h>

char* parse_json_to_string(const char* json_content, const char* filename);
void print_json_recursive(cJSON *json, char* result, int depth, size_t max_size);
void add_indent(char* result, int depth, size_t max_size);
char* get_current_time(void);

#endif // _JSON_UTILS_H_