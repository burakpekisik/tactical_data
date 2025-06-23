#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"

/**
 * @brief Veritabanı dosyasını zaman damgalı olarak yedekler.
 *
 * Bu fonksiyon, 'data/tactical_data.db' dosyasını 'data/backup/' klasörüne
 * YYYYMMDD_HHMMSS formatında zaman damgalı bir dosya olarak kopyalar.
 * Klasör yoksa otomatik olarak oluşturulur.
 *
 * @return 0 Başarılıysa, 1 Hata oluşursa
 */
int backup_database() {
    FILE *fptr1, *fptr2;
    char src_file[100] = CONFIG_DB_PATH;
    char backup_dir[100] = BACKUP_DIR;
    char backup_file[200];
    int c;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Klasör yoksa oluştur
    struct stat st = {0};
    if (stat(backup_dir, &st) == -1) {
        mkdir(backup_dir, 0700);
    }

    // Yedek dosya adını oluştur
    snprintf(backup_file, sizeof(backup_file), "%s/tactical_data_%04d%02d%02d_%02d%02d%02d.db", backup_dir,
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    // Kaynak dosyayı aç
    fptr1 = fopen(src_file, "rb");
    if (fptr1 == NULL)
    {
        printf("Cannot open file %s\n", src_file);
        return 1;
    }

    // Yedek dosyasını aç
    fptr2 = fopen(backup_file, "wb");
    if (fptr2 == NULL)
    {
        printf("Cannot open file %s\n", backup_file);
        fclose(fptr1);
        return 1;
    }

    // Dosya içeriğini kopyala
    while ((c = fgetc(fptr1)) != EOF)
    {
        fputc(c, fptr2);
    }

    printf("Yedekleme tamamlandı: %s\n", backup_file);

    fclose(fptr1);
    fclose(fptr2);
    return 0;
}