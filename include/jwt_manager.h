#ifndef JWT_MANAGER_H
#define JWT_MANAGER_H

char * generate_jwt(const char* user_id, const char* name, const char* surname, int privilege);
int verify_jwt(const char *token);
int get_jwt_privilege(const char *token);
char * get_user_id_and_name(const char * token);
int jwt_get_unit_id(const char* token);
char* jwt_get_my_information(const char* token);

#endif // JWT_MANAGER_H