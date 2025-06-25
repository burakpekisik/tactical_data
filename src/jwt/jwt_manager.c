#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <jwt.h>
#include "logger.h"
#include "config.h"

char * generate_jwt(const char* user_id, const char* name, const char* surname, int privilege) {
    jwt_t *jwt;
    char *out;
    time_t current_time = time(NULL);
    time_t expiration_time = current_time + 864000; // ten days
    PRINTF_LOG("JWT encode: sub(user_id)=%s, name=%s, surname=%s, privilege=%d, exp=%ld\n", user_id, name, surname, privilege, expiration_time);
    jwt_new(&jwt);
    jwt_add_grant_int(jwt, "exp", expiration_time);
    jwt_add_grant(jwt, "sub", user_id);
    jwt_add_grant(jwt, "name", name);
    jwt_add_grant(jwt, "surname", surname);
    jwt_add_grant_int(jwt, "privilege", privilege);
    jwt_set_alg(jwt, JWT_ALG_HS256, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    out = jwt_encode_str(jwt);
    jwt_free(jwt);
    return out;
}

int verify_jwt(const char *token) {
    jwt_t *jwt;
    int rc = jwt_decode(&jwt, token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET));
    PRINTF_LOG("verify_jwt: token=%s, decode_result=%d\n", token, rc);
    if (rc != 0) {
        fprintf(stderr, "JWT decode error: %d\n", rc);
        return -1; // JWT verification failed
    }
    // Check expiration
    time_t exp = jwt_get_grant_int(jwt, "exp");
    PRINTF_LOG("verify_jwt: exp=%ld, now=%ld\n", exp, time(NULL));
    if (exp < time(NULL)) {
        fprintf(stderr, "JWT expired\n");
        jwt_free(jwt);
        return -1; // JWT expired
    }
    jwt_free(jwt);
    return 0; // JWT is valid
}