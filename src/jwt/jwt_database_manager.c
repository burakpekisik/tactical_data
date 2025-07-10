#include "jwt_manager.h"
#include "database.h"
#include <jwt.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

// JWT'den user_id çekip db_select_user_by_id ile unit_id döndüren fonksiyon
int jwt_get_unit_id(const char* token) {
    jwt_t *jwt;
    if (jwt_decode(&jwt, token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) != 0) {
        fprintf(stderr, "JWT decode error\n");
        return -1; // JWT verification failed
    }
    const char *user_id = jwt_get_grant(jwt, "sub");
    if (!user_id) {
        jwt_free(jwt);
        return -1;
    }
    int user_id_int = atoi(user_id);
    int unit_id = -1;
    if (db_select_user_by_id(user_id_int, &unit_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != 0) {
        jwt_free(jwt);
        return -1; // Kullanıcı bulunamadı
    }
    jwt_free(jwt);
    return unit_id;
}

char* jwt_get_my_information(const char* token) {
    jwt_t *jwt;
    if (jwt_decode(&jwt, token, (const unsigned char*)CONFIG_JWT_SECRET, strlen(CONFIG_JWT_SECRET)) != 0) {
        fprintf(stderr, "JWT decode error\n");
        return NULL; // JWT verification failed
    }
    
    const char *user_id = jwt_get_grant(jwt, "sub");
    const char *name = jwt_get_grant(jwt, "name");
    const char *surname = jwt_get_grant(jwt, "surname");
    int privilege = jwt_get_grant_int(jwt, "privilege");
    
    if (!user_id || !name || !surname) {
        jwt_free(jwt);
        return NULL; // Bilgiler eksik
    }
    
    char *info = malloc(256);
    if (!info) {
        jwt_free(jwt);
        return NULL; // Bellek hatası
    }
    
    snprintf(info, 256, "User ID: %s, Name: %s, Surname: %s, Privilege: %d", user_id, name, surname, privilege);
    
    jwt_free(jwt);
    return info;
}