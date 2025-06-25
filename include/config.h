#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdint.h>

// Ağ konfigurasyonu
#define CONFIG_PORT 8080
#define CONFIG_UDP_PORT 8081
#define CONFIG_P2P_PORT 8082
#define CONFIG_CONTROL_PORT 9090
#define CONFIG_BUFFER_SIZE 8192
#define CONFIG_MAX_CLIENTS 10
#define CONFIG_MAX_FILENAME 256

// Queue konfigürasyonu
#define CONFIG_MAX_QUEUE_SIZE 20
#define CONFIG_QUEUE_TIMEOUT 300  // 5 dakika
#define CONFIG_QUEUE_CHECK_INTERVAL 2  // 2 saniye

// Thread gözleme konfigürasyonu
#define CONFIG_MAX_THREAD_NAME 64
#define CONFIG_THREAD_LOG_INTERVAL 10  // saniye

// Health Check konfigürasyonu
#define CONFIG_ENABLE_HEALTHCHECK_LOGGING 1
#define CONFIG_HEALTHCHECK_MIN_MESSAGE_SIZE 5

// Şifreleme konfigürasyonu - AES256 için 32 byte anahtar
#define CONFIG_CRYPTO_KEY_SIZE 32
#define CONFIG_AES_IV_SIZE 16

// ECDH konfigürasyonu
#define CONFIG_ECDH_KEY_SIZE ECC_PRV_KEY_SIZE
#define CONFIG_ECDH_PUBLIC_KEY_SIZE ECC_PUB_KEY_SIZE
#define CONFIG_ECDH_SHARED_SECRET_SIZE ECC_PUB_KEY_SIZE

// Argon2 konfigürasyonu
#define SALT_LENGTH 16
#define HASH_LENGTH 128

// Veritabanı konfigürasyonu
#define CONFIG_DB_PATH "data/tactical_data.db"
#define BACKUP_DIR "data/backup"

// JWT konfigürasyonu
#define CONFIG_JWT_SECRET "my_super_secret_key"

// Privilege seviyeleri
#define ADMIN_PRIVILEGE 1
#define USER_PRIVILEGE 0

#endif // _CONFIG_H_
