#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_utils.h"
#include "ecdh.h"

int main() {
    printf("ECDH Anahtar Değişimi Test Başlıyor...\n");
    
    // İki taraf için ECDH context'leri oluştur
    ecdh_context_t alice_ctx, bob_ctx;
    
    // Alice'in context'ini başlat
    if (!ecdh_init_context(&alice_ctx)) {
        printf("Alice context başlatılamadı\n");
        return 1;
    }
    
    // Bob'un context'ini başlat
    if (!ecdh_init_context(&bob_ctx)) {
        printf("Bob context başlatılamadı\n");
        return 1;
    }
    
    // Alice anahtar çifti üret
    printf("\nAlice anahtar çifti üretiliyor...\n");
    if (!ecdh_generate_keypair(&alice_ctx)) {
        printf("Alice anahtar çifti üretilemedi\n");
        return 1;
    }
    
    // Bob anahtar çifti üret
    printf("Bob anahtar çifti üretiliyor...\n");
    if (!ecdh_generate_keypair(&bob_ctx)) {
        printf("Bob anahtar çifti üretilemedi\n");
        return 1;
    }
    
    // Alice, Bob'un public key'i ile shared secret hesapla
    printf("\nAlice shared secret hesaplıyor...\n");
    if (!ecdh_compute_shared_secret(&alice_ctx, bob_ctx.public_key)) {
        printf("Alice shared secret hesaplayamadı\n");
        return 1;
    }
    
    // Bob, Alice'in public key'i ile shared secret hesapla
    printf("Bob shared secret hesaplıyor...\n");
    if (!ecdh_compute_shared_secret(&bob_ctx, alice_ctx.public_key)) {
        printf("Bob shared secret hesaplayamadı\n");
        return 1;
    }
    
    // Her iki taraf da AES anahtarını türet
    printf("\nAES anahtarları türetiliyor...\n");
    if (!ecdh_derive_aes_key(&alice_ctx)) {
        printf("Alice AES anahtarı türetemedi\n");
        return 1;
    }
    
    if (!ecdh_derive_aes_key(&bob_ctx)) {
        printf("Bob AES anahtarı türetemedi\n");
        return 1;
    }
    
    // Shared secret'lerin aynı olup olmadığını kontrol et
    if (memcmp(alice_ctx.shared_secret, bob_ctx.shared_secret, ECC_PUB_KEY_SIZE) == 0) {
        printf("✓ Shared secret'ler eşleşiyor!\n");
    } else {
        printf("✗ Shared secret'ler eşleşmiyor!\n");
        return 1;
    }
    
    // AES anahtarlarının aynı olup olmadığını kontrol et
    if (memcmp(alice_ctx.aes_key, bob_ctx.aes_key, CRYPTO_KEY_SIZE) == 0) {
        printf("✓ AES256 anahtarları eşleşiyor!\n");
    } else {
        printf("✗ AES256 anahtarları eşleşmiyor!\n");
        return 1;
    }
    
    // Anahtarları hex formatında göster
    printf("\nAlice AES256 Anahtarı: ");
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++) {
        printf("%02x", alice_ctx.aes_key[i]);
    }
    printf("\n");
    
    printf("Bob AES256 Anahtarı:   ");
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++) {
        printf("%02x", bob_ctx.aes_key[i]);
    }
    printf("\n");
    
    // Şifreleme testi
    printf("\nAES256 Şifreleme Testi...\n");
    const char* test_message = "Bu bir test mesajıdır - ECDH ile AES256 anahtarı üretildi!";
    uint8_t iv[CRYPTO_IV_SIZE];
    generate_random_iv(iv);
    
    // Alice mesajı şifreler
    crypto_result_t* encrypted = encrypt_data(test_message, alice_ctx.aes_key, iv);
    if (encrypted && encrypted->success) {
        printf("✓ Mesaj başarıyla şifrelendi\n");
        
        // Bob mesajı decrypt eder
        char* decrypted = decrypt_data(encrypted->data, encrypted->length, bob_ctx.aes_key, iv);
        if (decrypted) {
            printf("✓ Mesaj başarıyla decrypt edildi\n");
            printf("Orijinal:  %s\n", test_message);
            printf("Decrypted: %s\n", decrypted);
            
            if (strcmp(test_message, decrypted) == 0) {
                printf("✓ Mesajlar eşleşiyor! ECDH-AES256 entegrasyonu başarılı!\n");
            } else {
                printf("✗ Mesajlar eşleşmiyor!\n");
            }
            
            free(decrypted);
        } else {
            printf("✗ Mesaj decrypt edilemedi\n");
        }
        
        free_crypto_result(encrypted);
    } else {
        printf("✗ Mesaj şifrelenemedi\n");
    }
    
    // Context'leri temizle
    ecdh_cleanup_context(&alice_ctx);
    ecdh_cleanup_context(&bob_ctx);
    
    printf("\nECDH Anahtar Değişimi Test Tamamlandı!\n");
    
    return 0;
}
