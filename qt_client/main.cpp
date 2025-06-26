#include <QApplication>
#include <QQmlApplicationEngine>
#include <QQuickView>
#include <QtQuickControls2>
#include <QMessageBox>
#include "mainwindow.h"
#include "login_dialog.h"
#include "login_client.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QQuickStyle::setStyle("Material");

    QString jwtToken;
    QString loginError;
    QString serverHost = "127.0.0.1";
    int serverPort = 8080;

    LoginDialog loginDialog;
    while (true) {
        if (loginDialog.exec() == QDialog::Accepted) {
            QString username = loginDialog.getUsername();
            QString password = loginDialog.getPassword();
            // Sunucuya bağlanıp login doğrulaması yap
            jwtToken = LoginClient::login(serverHost, serverPort, username, password, loginError);
            if (!jwtToken.isEmpty()) {
                break;
            } else {
                QMessageBox::warning(nullptr, "Giriş Hatası", loginError);
            }
        } else {
            return 0; // Kullanıcı iptal etti
        }
    }

    MainWindow window;
    // Ana pencere açılırken otomatik olarak veri bağlantısı kur
    window.getClientWrapper()->setJwtToken(jwtToken);
    window.getClientWrapper()->connectToServer(serverHost, serverPort);
    window.show();
    return app.exec();
}
