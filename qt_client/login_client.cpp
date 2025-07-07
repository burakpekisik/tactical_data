#include "login_client.h"
#include <QTcpSocket>
#include <QDataStream>
#include <QDebug>

QString LoginClient::login(const QString& host, int port, const QString& username, const QString& password, QString& errorMsg)
{
    qDebug() << "[LOGIN] Sunucuya bağlanılıyor:" << host << port;
    QTcpSocket socket;
    socket.connectToHost(host, port);
    if (!socket.waitForConnected(3000)) {
        errorMsg = "Sunucuya bağlanılamadı!";
        qDebug() << "[LOGIN][ERROR] Bağlantı başarısız:" << socket.errorString();
        return QString();
    }
    qDebug() << "[LOGIN] Bağlantı başarılı, login mesajı gönderiliyor.";
    // Sunucu protokolüne uygun login mesajı: LOGIN:username:password\n
    QByteArray loginMsg = QString("LOGIN:%1:%2\n").arg(username, password).toUtf8();
    qDebug() << "[LOGIN] Gönderilen login mesajı (ham):" << loginMsg;

    socket.write(loginMsg);
    if (!socket.waitForBytesWritten(2000)) {
        errorMsg = "Veri gönderilemedi!";
        qDebug() << "[LOGIN][ERROR] Veri gönderilemedi.";
        return QString();
    }
    qDebug() << "[LOGIN] Yanıt bekleniyor...";
    if (!socket.waitForReadyRead(3000)) {
        errorMsg = "Sunucudan yanıt alınamadı!";
        qDebug() << "[LOGIN][ERROR] Sunucudan yanıt alınamadı.";
        return QString();
    }
    QByteArray response = socket.readAll();
    qDebug() << "[LOGIN] Sunucu yanıtı (ham):" << response.toHex();
    qDebug() << "[LOGIN] Sunucu yanıtı (string):" << QString::fromUtf8(response);

    // Yanıtı JSON parse etme! Protokole göre JWT:... veya FAIL gelir
    QString respStr = QString::fromUtf8(response).trimmed();
    if (respStr.startsWith("JWT:")) {
        QString token = respStr.mid(4).trimmed();
        if (!token.isEmpty()) {
            qDebug() << "[LOGIN] Giriş başarılı, token alındı.";
            return token;
        } else {
            errorMsg = "Sunucu geçersiz JWT döndürdü!";
            qDebug() << "[LOGIN][ERROR] Sunucu geçersiz JWT döndürdü!";
            return QString();
        }
    } else if (respStr == "FAIL") {
        errorMsg = "Kullanıcı adı veya şifre hatalı!";
        qDebug() << "[LOGIN][ERROR] Giriş başarısız: Kullanıcı adı veya şifre hatalı!";
        return QString();
    } else {
        errorMsg = "Sunucudan beklenmeyen yanıt alındı!";
        qDebug() << "[LOGIN][ERROR] Sunucudan beklenmeyen yanıt alındı!";
        return QString();
    }
}
