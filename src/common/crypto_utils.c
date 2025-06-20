/**
 * @file crypto_utils.c
 * @brief Kriptografik işlemler ve güvenlik fonksiyonları implementasyonu
 * @details Bu dosya, AES256-CBC şifreleme/şifre çözme, ECDH anahtar değişimi,
 *          PKCS7 padding, rastgele sayı üretimi ve hex encoding/decoding
 *          işlemlerinin implementasyonunu içerir. Güvenli veri transferi için
 *          gerekli tüm kriptografik primitive'leri sağlar.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 * @ingroup crypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "crypto_utils.h"
#include "config.h"
#include "aes.h"
#include "ecdh.h"

/**
 * @brief Metni AES256-CBC ile şifreler
 * @details Verilen plaintext'i AES256-CBC modunda şifreler. PKCS7 padding
 *          uygular ve şifreli veriyi crypto_result_t yapısında döner.
 * 
 * Şifreleme Süreci:
 * 1. Input uzunluğunu hesapla
 * 2. PKCS7 padding için gerekli boyutu belirle
 * 3. Padded data için bellek tahsis et
 * 4. PKCS7 padding uygula
 * 5. AES-CBC context başlat
 * 6. Şifreleme işlemini gerçekleştir
 * 
 * @param plaintext Şifrelenecek metin (null-terminated string)
 * @param key 32 byte AES256 anahtarı (ECDH'den türetilmiş)
 * @param iv 16 byte initialization vector (random olmalı)
 * @return crypto_result_t* Şifreleme sonucu (NULL: hata)
 * 
 * @note Dönen yapıdaki data pointer'ı free_crypto_result() ile temizlenmeli
 * @warning key ve iv NULL olmamalıdır
 * @warning Her şifreleme işlemi için farklı IV kullanılmalıdır
 * 
 * @see free_crypto_result(), apply_pkcs7_padding()
 */
crypto_result_t* encrypt_data(const char* plaintext, const uint8_t* key, const uint8_t* iv) {
    crypto_result_t* result = malloc(sizeof(crypto_result_t));
    if (result == NULL) {
        return NULL;
    }
    
    result->data = NULL;
    result->length = 0;
    result->success = 0;
    
    size_t input_length = strlen(plaintext);
    size_t padded_length = calculate_padded_length(input_length);
    
    // Padded data için bellek tahsis et
    uint8_t* padded_data = malloc(padded_length);
    if (padded_data == NULL) {
        free(result);
        return NULL;
    }
    
    // Veriyi kopyala ve padding uygula
    memcpy(padded_data, plaintext, input_length);
    apply_pkcs7_padding(padded_data, input_length, padded_length);
    
    // AES context oluştur
    struct AES_ctx ctx;
    if (key == NULL) {
        fprintf(stderr, "Error: AES anahtarı NULL - ECDH ile anahtar üretilmeli\n");
        free(padded_data);
        free(result);
        return NULL;
    }
    
    AES_init_ctx_iv(&ctx, key, iv);
    
    // CBC modunda şifrele
    AES_CBC_encrypt_buffer(&ctx, padded_data, padded_length);
    
    result->data = padded_data;
    result->length = padded_length;
    result->success = 1;
    
    return result;
}

/**
 * @brief Şifreli veriyi AES256-CBC ile çözer
 * @details Şifreli veriyi AES256-CBC modunda çözer, PKCS7 padding'i kaldırır
 *          ve orijinal plaintext'i null-terminated string olarak döner.
 * 
 * Şifre Çözme Süreci:
 * 1. Ciphertext boyutunu ve AES block alignment'ını kontrol et
 * 2. Decrypt için geçici buffer oluştur
 * 3. AES-CBC context başlat
 * 4. Şifre çözme işlemini gerçekleştir
 * 5. PKCS7 padding'i kaldır
 * 6. Null-terminated string oluştur
 * 
 * @param ciphertext Şifreli veri buffer'ı
 * @param length Şifreli veri uzunluğu (AES_BLOCKLEN'in katı olmalı)
 * @param key 32 byte AES256 anahtarı (şifrelemede kullanılan aynı anahtar)
 * @param iv 16 byte initialization vector (şifrelemede kullanılan aynı IV)
 * @return char* Çözülmüş plaintext (NULL: hata)
 * 
 * @note Dönen string free() ile serbest bırakılmalıdır
 * @warning length, AES_BLOCKLEN (16)'ın katı olmalıdır
 * @warning Şifrelemede kullanılan aynı key ve IV kullanılmalıdır
 * 
 * @see encrypt_data(), remove_pkcs7_padding()
 */
char* decrypt_data(const uint8_t* ciphertext, size_t length, const uint8_t* key, const uint8_t* iv) {
    if (ciphertext == NULL || length == 0 || length % AES_BLOCKLEN != 0) {
        return NULL;
    }
    
    // Decrypt için buffer oluştur
    uint8_t* decrypted_data = malloc(length);
    if (decrypted_data == NULL) {
        return NULL;
    }
    
    memcpy(decrypted_data, ciphertext, length);
    
    // AES context oluştur
    struct AES_ctx ctx;
    if (key == NULL) {
        fprintf(stderr, "Error: AES anahtarı NULL - ECDH ile anahtar üretilmeli\n");
        free(decrypted_data);
        return NULL;
    }
    
    AES_init_ctx_iv(&ctx, key, iv);
    
    // CBC modunda decrypt et
    AES_CBC_decrypt_buffer(&ctx, decrypted_data, length);
    
    // Padding'i kaldır
    size_t decrypted_length = length;
    if (remove_pkcs7_padding(decrypted_data, &decrypted_length) != 0) {
        free(decrypted_data);
        return NULL;
    }
    
    // Null-terminated string yap
    char* result = malloc(decrypted_length + 1);
    if (result == NULL) {
        free(decrypted_data);
        return NULL;
    }
    
    memcpy(result, decrypted_data, decrypted_length);
    result[decrypted_length] = '\0';
    
    free(decrypted_data);
    return result;
}

/**
 * @brief Crypto result yapısının belleğini güvenli şekilde temizler
 * @details crypto_result_t yapısındaki data pointer'ını ve yapının kendisini
 *          serbest bırakır. NULL pointer koruması sağlar.
 * 
 * @param result Temizlenecek crypto result yapısı (NULL olabilir)
 * 
 * @note NULL pointer kontrolü yapar, güvenli çağrı
 * @note data içeriği otomatik olarak serbest bırakılır
 * @warning Bu fonksiyon çağrıldıktan sonra result pointer geçersiz olur
 * 
 * @see encrypt_data()
 */
void free_crypto_result(crypto_result_t* result) {
    if (result != NULL) {
        if (result->data != NULL) {
            free(result->data);
        }
        free(result);
    }
}

/**
 * @brief PKCS7 padding için gerekli toplam boyutu hesaplar
 * @details Orijinal veri boyutundan PKCS7 padding uygulandıktan sonraki
 *          toplam boyutu hesaplar. AES block size (16 byte) alignment sağlar.
 * 
 * PKCS7 Padding Kuralı:
 * - Padding byte sayısı: AES_BLOCKLEN - (length % AES_BLOCKLEN)
 * - Her padding byte'ı, padding byte sayısına eşit değer içerir
 * - Minimum 1, maksimum AES_BLOCKLEN padding eklenir
 * 
 * @param original_length Orijinal veri uzunluğu
 * @return size_t Padding uygulandıktan sonraki toplam uzunluk
 * 
 * @note Sonuç her zaman AES_BLOCKLEN'in katıdır
 * @note Maksimum AES_BLOCKLEN byte padding eklenir
 * 
 * @example
 * @code
 * size_t padded = calculate_padded_length(10); // 10 -> 16 (6 byte padding)
 * size_t padded = calculate_padded_length(16); // 16 -> 32 (16 byte padding)
 * @endcode
 */
size_t calculate_padded_length(size_t original_length) {
    size_t padding_needed = AES_BLOCKLEN - (original_length % AES_BLOCKLEN);
    return original_length + padding_needed;
}

/**
 * @brief Veriye PKCS7 padding uygular
 * @details Orijinal verinin sonuna PKCS7 standardına uygun padding byte'ları ekler.
 *          Her padding byte'ı, toplam padding byte sayısına eşit değer içerir.
 * 
 * PKCS7 Padding Örneği:
 * - 10 byte veri + 6 byte padding: [...data...]06060606060606
 * - 15 byte veri + 1 byte padding: [...data...]01
 * - 16 byte veri + 16 byte padding: [...data...]10101010101010101010101010101010
 * 
 * @param data Padding uygulanacak veri buffer'ı (yeterli boyutta olmalı)
 * @param original_length Orijinal veri uzunluğu
 * @param padded_length Padding uygulandıktan sonraki toplam uzunluk
 * 
 * @note data buffer'ı padded_length boyutunda olmalıdır
 * @warning Buffer overflow koruması yok, boyut kontrolü çağıranın sorumluluğunda
 * 
 * @see calculate_padded_length(), remove_pkcs7_padding()
 */
void apply_pkcs7_padding(uint8_t* data, size_t original_length, size_t padded_length) {
    size_t padding_bytes = padded_length - original_length;
    
    for (size_t i = original_length; i < padded_length; i++) {
        data[i] = (uint8_t)padding_bytes;
    }
}

/**
 * @brief PKCS7 padding'i kaldırır ve orijinal veri uzunluğunu döner
 * @details Şifre çözüldükten sonra PKCS7 padding byte'larını kaldırır.
 *          Padding validasyonu yapar ve orijinal veri uzunluğunu günceller.
 * 
 * PKCS7 Padding Validasyonu:
 * 1. Son byte'ı padding değeri olarak oku
 * 2. Padding değerinin geçerli aralıkta olduğunu kontrol et (1-16)
 * 3. Son N byte'ın hepsinin aynı padding değerine sahip olduğunu doğrula
 * 4. Veri uzunluğunu padding byte sayısı kadar azalt
 * 
 * @param data Padding kaldırılacak veri buffer'ı
 * @param length [IN/OUT] Veri uzunluğu (işlem sonrası güncellenir)
 * @return int İşlem sonucu
 * @retval 0 Padding başarıyla kaldırıldı
 * @retval -1 Geçersiz padding veya hata
 * 
 * @note length parametresi referans olarak geçilir ve güncellenir
 * @warning Geçersiz padding durumunda -1 döner ve length değişmez
 * 
 * @see apply_pkcs7_padding(), decrypt_data()
 */
int remove_pkcs7_padding(uint8_t* data, size_t* length) {
    if (*length == 0) {
        return -1;
    }
    
    uint8_t padding_value = data[*length - 1];
    
    if (padding_value == 0 || padding_value > AES_BLOCKLEN) {
        return -1;
    }
    
    // Padding değerlerini kontrol et
    for (size_t i = *length - padding_value; i < *length; i++) {
        if (data[i] != padding_value) {
            return -1;
        }
    }
    
    *length -= padding_value;
    return 0;
}

/**
 * @brief Kriptografik olarak güvenli rastgele IV (Initialization Vector) üretir
 * @details 16 byte rastgele IV üretir. Şifreleme işlemlerinde replay attack
 *          koruması için her işlemde farklı IV kullanılmalıdır.
 * 
 * Rastgele Sayı Üretimi:
 * - İlk çağrıda time() ile seed ayarlanır
 * - Her byte için rand() % 256 kullanılır
 * - IV boyutu CRYPTO_IV_SIZE (16 byte) sabittir
 * 
 * @param iv 16 byte IV buffer'ı (çıkış parametresi)
 * 
 * @note IV her şifreleme işlemi için benzersiz olmalıdır
 * @note Aynı key ile aynı IV kullanımı güvenlik açığı oluşturur
 * @warning Prodüksiyon için /dev/urandom kullanımı önerilir
 * 
 * @see encrypt_data(), generate_secure_random()
 */
void generate_random_iv(uint8_t* iv) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    
    for (int i = 0; i < CRYPTO_IV_SIZE; i++) {
        iv[i] = (uint8_t)(rand() % 256);
    }
}

/**
 * @brief Binary veriyi hexadecimal string'e dönüştürür
 * @details Her byte'ı 2 karakter hex string'e çevirir (lowercase).
 *          Ağ üzerinden binary veri transferi için kullanılır.
 * 
 * Dönüştürme Formatı:
 * - Her byte -> 2 hex karakter (00-FF arası)
 * - Lowercase format (a-f)
 * - Null-terminated string
 * 
 * @param bytes Dönüştürülecek binary veri
 * @param length Binary veri uzunluğu
 * @return char* Hex string (NULL: bellek hatası)
 * 
 * @note Dönen string free() ile serbest bırakılmalıdır
 * @note Çıkış uzunluğu: (length * 2) + 1 (null terminator)
 * 
 * @example
 * @code
 * uint8_t data[] = {0x12, 0x34, 0xAB, 0xCD};
 * char* hex = bytes_to_hex(data, 4); // Sonuç: "1234abcd"
 * @endcode
 * 
 * @see hex_to_bytes()
 */
char* bytes_to_hex(const uint8_t* bytes, size_t length) {
    char* hex_string = malloc(length * 2 + 1);
    if (hex_string == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; i < length; i++) {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]);
    }
    
    hex_string[length * 2] = '\0';
    return hex_string;
}

/**
 * @brief Hexadecimal string'i binary veriye dönüştürür
 * @details Hex string'deki her 2 karakteri 1 byte'a çevirir.
 *          Ağ üzerinden alınan hex veriyi binary'e decode eder.
 * 
 * Dönüştürme Kuralları:
 * - Hex string uzunluğu çift sayı olmalı
 * - Geçerli hex karakterler: 0-9, a-f, A-F
 * - Her 2 hex karakter -> 1 byte
 * - Case-insensitive (büyük/küçük harf duyarsız)
 * 
 * @param hex Dönüştürülecek hex string
 * @param out_length [OUT] Çıkış binary veri uzunluğu
 * @return uint8_t* Binary veri (NULL: hata)
 * 
 * @note Dönen buffer free() ile serbest bırakılmalıdır
 * @warning Geçersiz hex karakter durumunda NULL döner
 * @warning Hex string uzunluğu tek sayı ise NULL döner
 * 
 * @example
 * @code
 * size_t len;
 * uint8_t* data = hex_to_bytes("1234abcd", &len); // len=4, data={0x12,0x34,0xAB,0xCD}
 * @endcode
 * 
 * @see bytes_to_hex()
 */
uint8_t* hex_to_bytes(const char* hex, size_t* out_length) {
    size_t hex_length = strlen(hex);
    if (hex_length % 2 != 0) {
        return NULL;
    }
    
    *out_length = hex_length / 2;
    uint8_t* bytes = malloc(*out_length);
    if (bytes == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; i < *out_length; i++) {
        int high = 0, low = 0;
        
        // High nibble
        char c = hex[i * 2];
        if (c >= '0' && c <= '9') high = c - '0';
        else if (c >= 'a' && c <= 'f') high = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') high = c - 'A' + 10;
        else {
            free(bytes);
            return NULL;
        }
        
        // Low nibble
        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') low = c - '0';
        else if (c >= 'a' && c <= 'f') low = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') low = c - 'A' + 10;
        else {
            free(bytes);
            return NULL;
        }
        
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    
    return bytes;
}

/**
 * @defgroup ecdh_functions ECDH Anahtar Yönetimi
 * @brief Elliptic Curve Diffie-Hellman anahtar değişimi fonksiyonları
 * @details Bu grup, güvenli anahtar değişimi için ECDH protokolünü
 *          implement eden fonksiyonları içerir. P-256 eğrisi kullanır.
 * @{
 */

/**
 * @brief Kriptografik olarak güvenli rastgele sayı üretir
 * @details /dev/urandom kullanarak güvenli rastgele byte'lar üretir.
 *          /dev/urandom mevcut değilse time-based fallback kullanır.
 * 
 * Güvenlik Seviyeleri:
 * 1. /dev/urandom (Linux/Unix) - Kriptografik güvenlik
 * 2. time() + rand() fallback - Temel güvenlik
 * 
 * @param buffer Rastgele veri yazılacak buffer
 * @param length Üretilecek rastgele byte sayısı
 * @return int İşlem sonucu
 * @retval 1 Başarılı rastgele sayı üretimi
 * @retval 0 Hata (buffer NULL veya length 0)
 * 
 * @note ECDH private key üretimi için kritik güvenlik fonksiyonu
 * @warning Zayıf rastgele sayı üretimi ECDH güvenliğini tehlikeye atar
 * 
 * @see ecdh_generate_keypair()
 */
int generate_secure_random(uint8_t* buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return 0;
    }
    
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        // Fallback to time-based random
        srand((unsigned int)time(NULL));
        for (size_t i = 0; i < length; i++) {
            buffer[i] = (uint8_t)(rand() & 0xFF);
        }
        return 1;
    }
    
    ssize_t bytes_read = read(fd, buffer, length);
    close(fd);
    
    return (bytes_read == (ssize_t)length) ? 1 : 0;
}

/**
 * @brief ECDH context yapısını başlatır
 * @details ECDH işlemleri için gerekli context yapısını sıfırlar ve başlatır.
 *          Tüm hassas veri alanlarını temizler.
 * 
 * @param ctx Başlatılacak ECDH context
 * @return int İşlem sonucu
 * @retval 1 Başarılı başlatma
 * @retval 0 Hata (ctx NULL)
 * 
 * @note Bu fonksiyon ECDH işlemlerinin ilk adımıdır
 * @note Context initialized flag'i false olarak ayarlanır
 * 
 * @see ecdh_generate_keypair(), ecdh_cleanup_context()
 */
int ecdh_init_context(ecdh_context_t* ctx) {
    if (ctx == NULL) {
        return 0;
    }
    
    memset(ctx, 0, sizeof(ecdh_context_t));
    ctx->initialized = 0;
    
    return 1;
}

/**
 * @brief ECDH anahtar çifti (public/private) üretir
 * @details Güvenli rastgele private key üretir ve karşılık gelen public key'i hesaplar.
 *          P-256 elliptic curve kullanır.
 * 
 * Anahtar Üretim Süreci:
 * 1. Güvenli rastgele private key üret (32 byte)
 * 2. ECC point multiplication ile public key hesapla
 * 3. Context'i initialized olarak işaretle
 * 
 * @param ctx ECDH context (önceden ecdh_init_context() ile başlatılmış olmalı)
 * @return int İşlem sonucu
 * @retval 1 Başarılı anahtar çifti üretimi
 * @retval 0 Hata (ctx NULL, rastgele sayı hatası, ECC hatası)
 * 
 * @note Bu fonksiyon sonrası public key ağ üzerinden paylaşılabilir
 * @warning Private key asla ağ üzerinden gönderilmemelidir
 * 
 * @see generate_secure_random(), ecdh_generate_keys()
 */
int ecdh_generate_keypair(ecdh_context_t* ctx) {
    if (ctx == NULL) {
        return 0;
    }
    
    // Rastgele private key üret
    if (!generate_secure_random(ctx->private_key, ECC_PRV_KEY_SIZE)) {
        printf("Error: Rastgele private key üretilemedi\n");
        return 0;
    }
    
    // Public key üret
    if (!ecdh_generate_keys(ctx->public_key, ctx->private_key)) {
        printf("Error: ECDH anahtar çifti üretilemedi\n");
        return 0;
    }
    
    ctx->initialized = 1;
    printf("ECDH anahtar çifti başarıyla üretildi\n");
    
    return 1;
}

/**
 * @brief Karşı tarafın public key'i ile shared secret hesaplar
 * @details ECDH algoritması ile kendi private key'i ve karşı tarafın public key'ini
 *          kullanarak shared secret hesaplar. Bu secret her iki tarafta da aynıdır.
 * 
 * ECDH Shared Secret Hesaplama:
 * shared_secret = private_key_self * public_key_other (ECC point multiplication)
 * 
 * @param ctx ECDH context (initialized olmalı)
 * @param other_public_key Karşı tarafın public key'i (32 byte)
 * @return int İşlem sonucu
 * @retval 1 Başarılı shared secret hesaplama
 * @retval 0 Hata (ctx NULL, other_public_key NULL, context initialize değil, ECC hatası)
 * 
 * @note Shared secret her iki tarafta da matematiksel olarak aynıdır
 * @note Bu secret'ten AES anahtarı türetilir
 * @warning other_public_key güvenilir kaynaktan alınmalıdır (MITM koruması)
 * 
 * @see ecdh_derive_aes_key(), ecdh_shared_secret()
 */
int ecdh_compute_shared_secret(ecdh_context_t* ctx, const uint8_t* other_public_key) {
    if (ctx == NULL || other_public_key == NULL || !ctx->initialized) {
        return 0;
    }
    
    // Shared secret hesapla
    if (!ecdh_shared_secret(ctx->private_key, other_public_key, ctx->shared_secret)) {
        printf("Error: Shared secret hesaplanamadı\n");
        return 0;
    }
    
    printf("Shared secret başarıyla hesaplandı\n");
    
    return 1;
}

/**
 * @brief Shared secret'ten AES256 anahtarı türetir
 * @details ECDH shared secret'ten AES256 şifreleme anahtarı türetir.
 *          Basit truncation kullanır (prodüksiyon için HKDF önerilir).
 * 
 * Key Derivation Yöntemi (Basit):
 * - Shared secret'in ilk 32 byte'ı AES256 anahtarı olarak kullanılır
 * - Shared secret 32 byte'tan küçükse sıfır padding uygulanır
 * 
 * @param ctx ECDH context (shared secret hesaplanmış olmalı)
 * @return int İşlem sonucu
 * @retval 1 Başarılı AES anahtarı türetimi
 * @retval 0 Hata (ctx NULL, context initialize değil)
 * 
 * @note Gerçek prodüksiyon için HKDF (RFC 5869) kullanılmalıdır
 * @note Türetilen anahtar AES256-CBC şifreleme için kullanılır
 * @warning Basit truncation method, ideal KDF değildir
 * 
 * @todo HKDF implementation ile replace edilmeli
 * @see ecdh_compute_shared_secret(), encrypt_data()
 */
int ecdh_derive_aes_key(ecdh_context_t* ctx) {
    if (ctx == NULL || !ctx->initialized) {
        return 0;
    }
    
    // Basit key derivation: shared secret'in ilk 32 byte'ını AES256 anahtarı olarak kullan
    // Gerçek uygulamada HKDF veya benzeri bir KDF kullanılmalı
    if (ECC_PUB_KEY_SIZE >= CRYPTO_KEY_SIZE) {
        memcpy(ctx->aes_key, ctx->shared_secret, CRYPTO_KEY_SIZE);
    } else {
        // Eğer shared secret 32 byte'tan küçükse, hash ile genişlet
        memcpy(ctx->aes_key, ctx->shared_secret, ECC_PUB_KEY_SIZE);
        // Kalan byte'ları 0 ile doldur (basit yaklaşım)
        memset(ctx->aes_key + ECC_PUB_KEY_SIZE, 0, CRYPTO_KEY_SIZE - ECC_PUB_KEY_SIZE);
    }
    
    printf("AES256 anahtarı shared secret'ten türetildi\n");
    
    return 1;
}

/**
 * @brief ECDH context'i güvenli şekilde temizler
 * @details Tüm hassas kriptografik verileri güvenli şekilde siler ve
 *          context'i temizlenmiş duruma getirir.
 * 
 * Temizlenen Hassas Veriler:
 * - Private key (32 byte)
 * - Shared secret (32 byte)  
 * - AES anahtarı (32 byte)
 * - Initialized flag
 * 
 * @param ctx Temizlenecek ECDH context (NULL olabilir)
 * 
 * @note NULL pointer kontrolü yapar, güvenli çağrı
 * @note memset() ile hassas veriler sıfırlanır
 * @note Public key temizlenmez (hassas değil)
 * @warning Bu fonksiyon sonrası context yeniden başlatılmalıdır
 * 
 * @see ecdh_init_context()
 */
void ecdh_cleanup_context(ecdh_context_t* ctx) {
    if (ctx != NULL) {
        // Hassas verileri güvenli bir şekilde temizle
        memset(ctx->private_key, 0, sizeof(ctx->private_key));
        memset(ctx->shared_secret, 0, sizeof(ctx->shared_secret));
        memset(ctx->aes_key, 0, sizeof(ctx->aes_key));
        ctx->initialized = 0;
    }
}

/** @} */ // ecdh_functions group sonu
