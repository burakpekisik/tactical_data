#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdint.h>

// Network Configuration
#define CONFIG_PORT 8080
#define CONFIG_BUFFER_SIZE 8192
#define CONFIG_MAX_CLIENTS 10
#define CONFIG_MAX_FILENAME 256

// Crypto Configuration
#define CONFIG_CRYPTO_KEY_SIZE 16
extern const uint8_t CONFIG_DEFAULT_KEY[CONFIG_CRYPTO_KEY_SIZE];

// Database Configuration
#define CONFIG_DB_PATH "data/tactical_data.db"

#endif // _CONFIG_H_
