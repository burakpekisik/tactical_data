#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <jwt.h>

char * generate_jwt() {
    jwt_t *jwt;
    char *out;
    time_t current_time = time(NULL);
    time_t expiration_time = current_time + 864000; // ten days

    jwt_new(&jwt);
    jwt_add_grant_int(jwt, "exp", expiration_time);
    jwt_add_grant(jwt, "sub", "public_key");
    jwt_set_alg(jwt, JWT_ALG_HS256, (const unsigned char*)"private_key", strlen("private_key"));
    out = jwt_encode_str(jwt);
    printf("%s\n", out);
    jwt_free(jwt);
    return out;
}

int verify_jwt(const char *token) {
    jwt_t *jwt;
    int rc = jwt_decode(&jwt, token, (const unsigned char*)"public_key", strlen("public_key"));
    if (rc != 0) {
        fprintf(stderr, "JWT decode error: %d\n", rc);
        return -1; // JWT verification failed
    }
    
    // Check expiration
    time_t exp = jwt_get_grant_int(jwt, "exp");
    if (exp < time(NULL)) {
        fprintf(stderr, "JWT expired\n");
        jwt_free(jwt);
        return -1; // JWT expired
    }

    jwt_free(jwt);
    return 0; // JWT is valid
}

