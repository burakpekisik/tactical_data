#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

int parse_protocol_message(const char* message, char** command, char** filename, char** content);
int parse_encrypted_protocol_message(const char* message, char** command, char** filename, char** hex_data, char** jwt_token);

#endif // PROTOCOL_PARSER_H