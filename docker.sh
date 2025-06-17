#!/bin/bash

# Tactical Data Transfer - Docker Management Script
# Bu script projeyi Docker ile kolayca yönetmenizi sağlar

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_usage() {
    echo "Kullanım: $0 [KOMUT]"
    echo ""
    echo "Komutlar:"
    echo "  build     - Server ve client image'larını derle"
    echo "  server    - Sadece server'ı başlat"
    echo "  client    - Client'ı interactive modda başlat"
    echo "  both      - Server ve client'ı birlikte başlat"
    echo "  stop      - Tüm container'ları durdur"
    echo "  clean     - Container'ları ve image'ları temizle"
    echo "  logs      - Server loglarını göster"
    echo "  status    - Container durumlarını göster"
    echo "  db-admin  - Database admin console'u açar"
    echo "  db-test   - Database test araçlarını çalıştır"
    echo "  db-backup - Database'i yedekle"
    echo ""
    echo "Örnekler:"
    echo "  $0 build    # Image'ları derle"
    echo "  $0 server   # Server'ı başlat"
    echo "  $0 client   # Client'ı başlat"
}

build_images() {
    echo -e "${GREEN}Docker image'ları derleniyor...${NC}"
    docker compose build
    echo -e "${GREEN}Image'lar başarıyla derlendi!${NC}"
}

start_server() {
    echo -e "${GREEN}Encrypted JSON Server başlatılıyor...${NC}"
    docker compose up -d encrypted-server
    echo -e "${GREEN}Server başlatıldı! Port 8080'de dinliyor.${NC}"
    echo -e "${YELLOW}Logları görmek için: $0 logs${NC}"
}

start_client() {
    echo -e "${GREEN}Encrypted JSON Client başlatılıyor...${NC}"
    echo -e "${YELLOW}Client interactive modda açılacak. Çıkmak için Ctrl+C kullanın.${NC}"
    sleep 2
    docker compose run --rm encrypted-client
}

start_both() {
    echo -e "${GREEN}Server ve Client başlatılıyor...${NC}"
    docker compose up encrypted-server &
    sleep 5
    echo -e "${YELLOW}5 saniye sonra client başlatılacak...${NC}"
    sleep 5
    docker compose run --rm encrypted-client
}

stop_containers() {
    echo -e "${YELLOW}Container'lar durduruluyor...${NC}"
    docker compose down
    echo -e "${GREEN}Tüm container'lar durduruldu!${NC}"
}

clean_all() {
    echo -e "${YELLOW}Container'lar ve image'lar temizleniyor...${NC}"
    docker compose down --rmi all --volumes --remove-orphans
    echo -e "${GREEN}Temizlik tamamlandı!${NC}"
}

show_logs() {
    echo -e "${GREEN}Server logları:${NC}"
    docker compose logs -f encrypted-server
}

show_status() {
    echo -e "${GREEN}Container durumları:${NC}"
    docker compose ps
    echo ""
    echo -e "${GREEN}Docker image'ları:${NC}"
    docker images | grep "tactical\|encrypted"
    echo ""
    echo -e "${GREEN}Database volume durumu:${NC}"
    docker volume ls | grep tactical
}

start_db_admin() {
    echo -e "${GREEN}Database Admin Console başlatılıyor...${NC}"
    echo -e "${YELLOW}SQLite console'u açılacak. Çıkmak için .quit yazın.${NC}"
    docker compose --profile admin run --rm db-admin sqlite3 /app/data/tactical_data.db
}

run_db_test() {
    echo -e "${GREEN}Database test araçları çalıştırılıyor...${NC}"
    docker compose --profile admin run --rm db-admin bash -c "
        echo 'Database test araçları derleniyor...'
        make db-tools
        echo 'Test verileri kontrol ediliyor...'
        ./build/db_test
    "
}

backup_database() {
    echo -e "${GREEN}Database yedekleniyor...${NC}"
    BACKUP_FILE="tactical_data_backup_$(date +%Y%m%d_%H%M%S).db"
    docker compose --profile admin run --rm -v "$(pwd):/backup" db-admin bash -c "
        cp /app/data/tactical_data.db /backup/$BACKUP_FILE
        echo 'Database yedeklendi: $BACKUP_FILE'
    "
    echo -e "${GREEN}Yedek dosyası: $BACKUP_FILE${NC}"
}

case "${1:-}" in
    build)
        build_images
        ;;
    server)
        start_server
        ;;
    client)
        start_client
        ;;
    both)
        start_both
        ;;
    stop)
        stop_containers
        ;;
    clean)
        clean_all
        ;;
    logs)
        show_logs
        ;;
    status)
        show_status
        ;;
    db-admin)
        start_db_admin
        ;;
    db-test)
        run_db_test
        ;;
    db-backup)
        backup_database
        ;;
    help|--help|-h)
        print_usage
        ;;
    *)
        echo -e "${RED}Hata: Geçersiz komut '${1:-}'${NC}"
        echo ""
        print_usage
        exit 1
        ;;
esac
