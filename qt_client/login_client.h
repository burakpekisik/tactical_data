#ifndef LOGIN_CLIENT_H
#define LOGIN_CLIENT_H

#include <QString>

class LoginClient {
public:
    // Sunucuya bağlanıp login doğrulaması yapar
    // Başarılıysa JWT veya session string döndürür, başarısızsa boş string
    static QString login(const QString& host, int port, const QString& username, const QString& password, QString& errorMsg);
};

#endif // LOGIN_CLIENT_H
