#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "argon2.h"
#include "config.h"

/**
 * @brief Rastgele salt üretir (ASCII karakterlerden)
 * @details Belirtilen uzunlukta rastgele karakterlerden oluşan bir salt üretir.
 *
 * @param salt [OUT] Üretilen salt karakter dizisi
 * @param length [IN] Salt uzunluğu (null karakter dahil)
 */
void generate_salt(char *salt, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=";
    size_t charset_size = sizeof(charset) - 1;
    srand((unsigned int)time(NULL) ^ (unsigned int)rand());
    for (size_t i = 0; i < length - 1; i++) {
        salt[i] = charset[rand() % charset_size];
    }
    salt[length - 1] = '\0';
}

/**
 * @brief Şifreyi ve salt'ı birleştirip hashler
 * @details Rastgele salt üretir, salt+şifre birleştirip Argon2 ile hashler.
 *
 * @param password [IN] Kullanıcı şifresi
 * @param salt_out [OUT] Üretilen salt
 * @param hash_out [OUT] Üretilen hash (encoded)
 * @return int Argon2 dönüş kodu (0 başarılı)
 */
int hash_password_with_salt(const char *password, char *salt_out, char *hash_out) {
    char salted_pwd[SALT_LENGTH + 256];
    generate_salt(salt_out, SALT_LENGTH);
    snprintf(salted_pwd, sizeof(salted_pwd), "%s%s", salt_out, password);
    int result = argon2id_hash_encoded(
        3, 1 << 16, 1,
        salted_pwd, strlen(salted_pwd),
        salt_out, strlen(salt_out),
        32, hash_out, HASH_LENGTH
    );
    return result;
}

/**
 * @brief Şifre doğrulama işlemi
 * @details Kullanıcıdan gelen şifreyi ve veritabanındaki salt'ı alıp doğrulama yapar.
 *
 * @param password [IN] Kullanıcıdan gelen şifre
 * @param salt [IN] Veritabanındaki salt
 * @param hash [IN] Veritabanındaki hash (encoded)
 * @return int Argon2 dönüş kodu (0 başarılı)
 */
int verify_password_with_salt(const char *password, const char *salt, const char *hash) {
    char salted_pwd[SALT_LENGTH + 256];
    snprintf(salted_pwd, sizeof(salted_pwd), "%s%s", salt, password);
    return argon2id_verify(hash, salted_pwd, strlen(salted_pwd));
}
