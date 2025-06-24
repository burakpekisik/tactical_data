#include <stdio.h>
#include <string.h>
#include "database.h"
#include "config.h"

#define INPUT_SIZE 128

int main() {
    char username[INPUT_SIZE];
    char password[INPUT_SIZE];

    if (db_init(CONFIG_DB_PATH) != 0) {
        printf("Veritabanı başlatılamadı!\n");
        return 1;
    }

    printf("Kullanıcı adı: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("Şifre: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    char *res = login_user_with_argon2(username, password);
    if (res == NULL) {
        printf("Giriş başarısız! Kullanıcı adı veya şifre yanlış.\n");
    } else {
        printf("Giriş başarılı! Kullanıcı JWT: %s\n", res);
    }

    db_close();
    return 0;
}