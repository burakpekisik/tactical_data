#ifndef JWT_MANAGER_H
#define JWT_MANAGER_H

char * generate_jwt(const char* user_id);
int verify_jwt(const char *token);

#endif // JWT_MANAGER_H