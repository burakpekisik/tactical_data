# TCP Server-Client + JSON File Transfer System

Bu proje, C dilinde yazılmış TCP server-client mesajlaşma sistemi ve JSON dosya transfer & parse sistemi içerir.

## 📁 Dosyalar

### Temel TCP Sistem:
- `server.c` - Basit TCP server
- `client.c` - Basit TCP client
- `json.c` - Standalone JSON parser

### JSON File Transfer Sistemi:
- `json_server.c` - JSON dosya parse sunucusu
- `json_client.c` - JSON dosya gönderme istemcisi
- `data.json` - Örnek JSON dosyası

### Yardımcı:
- `Makefile` - Derleme ve çalıştırma komutları

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
```bash
sudo apt update
sudo apt install libcjson-dev gcc make
```

### 1. Derleme
```bash
# Tüm programları derle
make

# Veya sadece JSON sistemi:
make json_server json_client
```

## 📡 JSON File Transfer Sistemi

### Protocol Format
```
FILENAME:CONTENT
Örnek: data.json:{"name":"Burak","age":30}
```

### Server Başlatma
```bash
# Terminal 1'de JSON server'ı başlat
make run-json-server
```

### Client Kullanımı
```bash
# Terminal 2'de JSON client'ı başlat
make run-json-client

# Dosya adını gir (örnek: data.json)
# Server parse edip sonucu döndürür
```

## 🔧 Özellikler

### JSON File Transfer:
- ✅ Dosya ismi + içerik protokolü
- ✅ Modüler yapı (ayrı fonksiyonlar)
- ✅ Comprehensive JSON parsing
- ✅ Error handling
- ✅ Memory management
- ✅ Multiple client support
- ✅ Real-time parsing results
- ✅ Timestamp logging

### Desteklenen JSON Tipleri:
- String, Number (Integer/Double)
- Boolean, Array, Object, null
- Nested structures

## 📊 Örnek Kullanım

**JSON Server Çıktısı:**
```
JSON Server - Dosya parse sunucusu
==================================
Server baslatildi
Port 8080'de JSON parse istekleri bekleniyor...

Yeni client baglandi: 127.0.0.1:45958
[10:22:53] Mesaj alindi (162 byte)
Dosya: data.json
JSON parse ediliyor...
Parse sonucu gonderildi
```

**JSON Client Çıktısı:**
```
JSON Client - Dosya gonderme istemcisi
=====================================
Server'a basariyla baglandi

Dosya adi: data.json
Dosya okundu: data.json (152 byte)
Server'a gonderiliyor...
Basariyla gonderildi (162 byte)

Server yaniti:
=============
JSON Parse Sonucu
================
Dosya: data.json
Zaman: 10:22:53
Parse Edildi:
-------------
name: "Burak" (String)
age: 30 (Integer)
isEmployed: true (Boolean)
skills: Array (4 oge)
  [0]: "C"
  [1]: "C++"
  [2]: "Python"
  [3]: "JavaScript"
=============
```

## 🛠️ Makefile Komutları

```bash
make                    # Tüm programları derle
make json_server        # JSON server'ı derle
make json_client        # JSON client'ı derle
make clean              # Temizlik
make run-json-server    # JSON server'ı çalıştır
make run-json-client    # JSON client'ı çalıştır
make help               # Yardım
```

## 🔧 Teknik Detaylar

- **Protocol:** Custom "FILENAME:CONTENT" format
- **Port:** 8080
- **Buffer Size:** 4KB
- **JSON Library:** cJSON
- **Memory:** Dynamic allocation
- **Architecture:** Modular functions
- **Error Handling:** Comprehensive validation

## 🎯 İş Akışı

1. Client dosya adını girer
2. Client dosyayı okur ve "FILENAME:CONTENT" formatında gönderir
3. Server protocol mesajını parse eder
4. Server JSON içeriğini parse eder
5. Server formatlanmış sonucu döndürür
6. Client sonucu gösterir
