#ifndef TACTICAL_DATA_HANDLER_H
#define TACTICAL_DATA_HANDLER_H

void handle_encrypted_tactical_data(const char* decrypted_json, const char* jwt_token, const char* filename, int client_socket, const char* client_ip, int client_port, char* out, size_t out_size);

#endif // TACTICAL_DATA_HANDLER_H