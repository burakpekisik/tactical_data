#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/database.h"
#include "../../include/config.h"
#include "../../include/argon2.h"
#include "config.h"

#define INPUT_SIZE 128

int main() {
    char username[INPUT_SIZE];
    char name[INPUT_SIZE];
    char surname[INPUT_SIZE];
    char password[INPUT_SIZE];
    int unit_id;

    if (db_init(CONFIG_DB_PATH) != 0) {
        printf("Veritabanı başlatılamadı!\n");
        return 1;
    }

    printf("Kullanıcı adı: ");
    fgets(username, INPUT_SIZE, stdin);
    username[strcspn(username, "\n")] = 0;

    printf("İsim: ");
    fgets(name, INPUT_SIZE, stdin);
    name[strcspn(name, "\n")] = 0;

    printf("Soyisim: ");
    fgets(surname, INPUT_SIZE, stdin);
    surname[strcspn(surname, "\n")] = 0;

    printf("Birim ID (sayı): ");
    scanf("%d", &unit_id);
    getchar(); // newline temizle

    printf("Şifre: ");
    fgets(password, INPUT_SIZE, stdin);
    password[strcspn(password, "\n")] = 0;

    if (register_user_with_argon2(unit_id, username, name, surname, password) == 1) {
        printf("Kullanıcı başarıyla kaydedildi!\n");
    } else {
        printf("Kullanıcı kaydı başarısız!\n");
    }

    db_close();
    return 0;
}
