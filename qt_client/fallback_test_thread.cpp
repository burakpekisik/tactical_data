#include "fallback_test_thread.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

FallbackTestThread::FallbackTestThread(const QString& host, int port, QObject* parent)
    : QThread(parent), host(host), port(port) {}

void FallbackTestThread::run() {
    emit fallbackTestResult("INFO", true, "Tüm bağlantı türleri test ediliyor...");

    // TCP
    emit fallbackTestResult("TCP", false, "TCP bağlantısı test ediliyor...");
    bool tcpOk = testTcp();
    emit fallbackTestResult("TCP", tcpOk, tcpOk ? "TCP bağlantısı başarılı" : "TCP bağlantısı başarısız");

    // UDP
    emit fallbackTestResult("UDP", false, "UDP bağlantısı test ediliyor...");
    bool udpOk = testUdp();
    emit fallbackTestResult("UDP", udpOk, udpOk ? "UDP bağlantısı başarılı" : "UDP bağlantısı başarısız");

    // P2P
    emit fallbackTestResult("P2P", false, "P2P bağlantısı test ediliyor...");
    bool p2pOk = testP2p();
    emit fallbackTestResult("P2P", p2pOk, p2pOk ? "P2P bağlantısı başarılı" : "P2P bağlantısı başarısız");

    emit fallbackTestResult("INFO", true, "Tüm bağlantı testleri tamamlandı");
    emit allTestsFinished();
}

bool FallbackTestThread::testTcp() {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.toStdString().c_str(), &addr.sin_addr) <= 0) {
        ::close(sock);
        return false;
    }
    bool ok = (::connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0);
    ::close(sock);
    return ok;
}

bool FallbackTestThread::testUdp() {
    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port + 1);
    if (::inet_pton(AF_INET, host.toStdString().c_str(), &addr.sin_addr) <= 0) {
        ::close(sock);
        return false;
    }
    const char* msg = "PING";
    sendto(sock, msg, strlen(msg), 0, (sockaddr*)&addr, sizeof(addr));
    struct timeval tv = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[64];
    ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, nullptr, nullptr);
    ::close(sock);
    return n > 0;
}

bool FallbackTestThread::testP2p() {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port + 2);
    if (::inet_pton(AF_INET, host.toStdString().c_str(), &addr.sin_addr) <= 0) {
        ::close(sock);
        return false;
    }
    bool ok = (::connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0);
    ::close(sock);
    return ok;
}
