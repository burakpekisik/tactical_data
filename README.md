# Tactical Data Server - Modular Network Communication System

🚀 **Modern, çok protokollü, threaded tactical data server/client sistemi**

Bu proje, C dilinde yazılmış gelişmiş bir network communication sistemi olup tactical data transfer, encryption, multi-protocol support ve real-time monitoring özellikleri içerir.

## ✨ Özellikler

### 🌐 Multi-Protocol Support
- **TCP Server** (Port 8080) - Reliable connections, persistent threads
- **UDP Server** (Port 8081) - Fast datagram communication  
- **P2P Node** (Port 8082) - Peer-to-peer messaging (future)
- **Control Interface** (Port 9090) - Management & monitoring

### 🔐 Security & Encryption
- **AES Encryption** - Tactical data encryption/decryption
- **Hex Encoding** - Safe data transmission
- **Key Management** - Configurable encryption keys

### 📊 Database Integration
- **SQLite Database** - Persistent tactical data storage
- **CRUD Operations** - Full database manipulation
- **JSON to Database** - Automatic tactical data parsing & storage

### 🧵 Advanced Threading
- **Multi-threaded Server** - Concurrent client handling
- **Thread Monitoring** - Real-time thread statistics
- **Connection Queue** - Client queueing system
- **Resource Monitoring** - Memory & CPU usage tracking

### 🔧 Management & Monitoring
- **Real-time Statistics** - Connections, threads, health checks
- **Control Interface** - Server management via TCP commands
- **Health Checks** - Docker health monitoring
- **Logging System** - Comprehensive activity logging

## 📁 Proje Yapısı

```
send_tactical_data/
├── 📂 src/                          # Source code
│   ├── 📂 server/                   # Main server
│   │   └── encrypted_server.c       # Multi-protocol server
│   ├── 📂 client/                   # Client application  
│   │   └── encrypted_client.c       # TCP/UDP fallback client
│   ├── 📂 connection/               # Protocol implementations
│   │   ├── connection_manager.c     # Protocol coordinator
│   │   ├── tcp_connection.c         # TCP server logic
│   │   ├── udp_connection.c         # UDP server logic
│   │   └── p2p_connection.c         # P2P node logic
│   ├── 📂 control/                  # Management interface
│   │   └── control_interface.c      # Server control & monitoring
│   ├── 📂 thread/                   # Threading system
│   │   └── thread_monitor.c         # Thread & resource monitoring
│   ├── 📂 database/                 # Database operations
│   │   ├── create.c, insert.c       # CRUD operations
│   │   ├── select.c, update.c       
│   │   ├── delete.c, open.c         
│   │   └── db_test_utils.c          # Database utilities
│   ├── 📂 common/                   # Shared utilities
│   │   ├── json_utils.c             # JSON parsing (tactical data)
│   │   └── crypto_utils.c           # Encryption/decryption
│   └── 📂 crypto/                   # Cryptography
│       └── aes.c                    # AES implementation
├── 📂 include/                      # Header files
├── 📂 data/                         # Data files
│   ├── data.json                    # Sample tactical data
│   └── tactical_data.db             # SQLite database
├── 📂 build/                        # Compiled binaries
├── 🐳 Docker files                  # Container setup
├── 🔧 Makefile                      # Build system
└── 📚 README.md                     # This file
```

## 🚀 Hızlı Başlangıç

### 🐳 Docker ile Çalıştırma (Önerilen)

```bash
# 1. Projeyi klonla
git clone https://github.com/burakpekisik/tactical_data
cd tactical_data

```

### 🛠️ Docker Yardımcı Script'leri

```bash
./docker.sh build          # Image'ları derle
./docker.sh server         # Server'ı başlat
./docker.sh client         # Client'ı başlat  
./docker.sh both           # Server + Client
./docker.sh stop           # Container'ları durdur
./docker.sh clean          # Temizlik
./docker.sh logs           # Server logları
./docker.sh status         # Container durumu
```

### 🖥️ Manuel Kurulum

#### Gereksinimler
```bash
sudo apt update
sudo apt install gcc make libcjson-dev libsqlite3-dev libssl-dev
```

#### Derleme ve Çalıştırma  
```bash
# Tüm bileşenleri derle
make clean && make

# Server'ı başlat
./build/encrypted_server veya ./docker.sh server

# Client'ı başlat (başka terminal)
./build/encrypted_client veya ./docker.sh client
```

## 🎮 Kullanım

### 📡 Server Management

Server çalışırken control interface üzerinden yönetilebilir:

```bash
# Control interface'e bağlan (Port 9090)
nc localhost 9090 veya ./docker-control.sh cmd

# Kullanılabilir komutlar:
list         # Server durumu
start_tcp    # TCP server başlat
stop_tcp     # TCP server durdur  
start_udp    # UDP server başlat
stop_udp     # UDP server durdur
stats        # İstatistikler
healthcheck  # Health check
help         # Yardım
quit         # Çıkış
```

### 📤 Client Kullanımı

Client otomatik protokol seçimi yapar:
1. **TCP'ye bağlanmaya çalışır** (Port 8080)
2. **Başarısız olursa UDP'ye geçer** (Port 8081)

```bash
# Menu seçenekleri:
1. Normal JSON dosyasi gonder     # Düz JSON gönder
2. Sifreli JSON dosyasi gonder    # Encrypted JSON gönder  
3. Cikis                          # Çıkış
```

### 🗃️ Tactical Data Format

```json
{
  "unit_id": "BİRİM-01",
  "status": "Tehlike", 
  "latitude": 39.920800,
  "longitude": 32.854100,
  "description": "Tactical unit description...",
  "timestamp": 1718572220
}
```

## 🔧 Configuration

### 📋 Port Konfigürasyonu
- **TCP Server**: 8080
- **UDP Server**: 8081  
- **P2P Node**: 8082
- **Control Interface**: 9090

### ⚙️ Advanced Settings (`include/config.h`)
```c
#define CONFIG_PORT 8080              // TCP port
#define CONFIG_UDP_PORT 8081          // UDP port
#define CONFIG_P2P_PORT 8082          // P2P port
#define CONFIG_CONTROL_PORT 9090      // Control port
#define CONFIG_BUFFER_SIZE 8192       // Buffer size
#define CONFIG_MAX_CLIENTS 10         // Max concurrent clients
#define CONFIG_CRYPTO_KEY_SIZE 16     // Encryption key size
```

## 📊 Monitoring & Statistics

### 🔍 Real-time Monitoring
Server sürekli olarak şu bilgileri sağlar:
- **Active Threads**: Aktif client thread'leri
- **Connection Stats**: TCP/UDP/P2P bağlantı durumları  
- **Database Operations**: CRUD işlem sayıları
- **Health Checks**: Docker health check durumu
- **Memory Usage**: Bellek kullanımı
- **CPU Time**: İşlemci zamanı

### 📈 Statistics Output
```
=== THREAD & QUEUE ISTATISTIKLERI ===
Server uptime: 180 saniye (3 dakika)
Aktif thread sayisi: 2/10
Queue boyutu: 0/20
Toplam baglanti: 15
Health check sayisi: 6
Gercek client baglanti: 2
Aktif thread'ler:
- client_172.18.0.3_56356 (Socket: 7, Sure: 45 s)
- client_172.18.0.3_56357 (Socket: 8, Sure: 12 s)
Bellek kullanimi: 11324 KB
CPU zamanı: 0.045231 saniye
====================================
```

## 🔐 Security

### 🛡️ Encryption
- **AES-128 Encryption**: Tactical data için güvenli şifreleme
- **Random IV**: Her şifreleme için unique IV
- **Hex Encoding**: Binary data'nın güvenli transferi

### 🔑 Key Management
Default key configuration'da tanımlı, production'da değiştirilmeli.

## 🐳 Docker Integration

### 📦 Multi-Container Setup
- **tactical-data-server**: Main server container
- **tactical-data-client**: Interactive client container
- **tactical-network**: Bridge network
- **Volume Mapping**: Database persistence

### 🔍 Health Checks
Docker health check control interface üzerinden gerçekleşir:
```bash
# Health check komutu
echo 'healthcheck' | nc localhost 9090
```

## 🧪 Testing

### 🗄️ Database Tests
```bash
./build/db_test_standalone    # Standalone database test
./build/db_test_operations    # CRUD operations test
```

### 🌐 Network Tests  
```bash
# Control interface test
./docker-control.sh cmd list
./docker-control.sh cmd stats

# Manual protocol test
nc localhost 8080   # TCP test
nc -u localhost 8081 # UDP test
```

## 🎯 Use Cases

### 🚁 Tactical Operations
- **Unit Tracking**: Birim konumları ve durumları
- **Status Updates**: Real-time durum güncellemeleri  
- **Encrypted Communication**: Güvenli veri transferi
- **Multi-Protocol**: Farklı network koşullarında çalışma

### 🏗️ System Integration
- **Microservices**: Diğer sistemlerle entegrasyon
- **Database Integration**: Tactical data persistence
- **Monitoring**: Real-time sistem monitoring
- **Scalability**: Multi-threaded architecture

## 🛠️ Development

### 🔨 Build System
```bash
make clean              # Temizlik
make all               # Tüm bileşenleri derle
make encrypted-server  # Sadece server
make encrypted-client  # Sadece client
make tests            # Test programs
```

### 🐛 Debugging
```bash
# Server'ı debug modda çalıştır
gdb ./build/encrypted_server

# Thread monitoring
ps -eLf | grep encrypted_server
```

### 📚 Code Organization
- **Modular Design**: Her protokol ayrı dosyada
- **Header Organization**: Temiz interface definitions
- **Error Handling**: Comprehensive error management
- **Memory Management**: Proper allocation/deallocation

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)  
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **cJSON Library**: JSON parsing capabilities
- **SQLite**: Database functionality  
- **OpenSSL**: Cryptographic functions
- **Docker**: Containerization support

---

**🚀 Modern tactical data communication made simple and secure!**
