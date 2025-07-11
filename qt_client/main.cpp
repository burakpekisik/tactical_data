#include <QApplication>
#include <QQmlApplicationEngine>
#include <QQuickView>
#include <QtQuickControls2>
#include <QMessageBox>
#include <QIcon>
#include "mainwindow.h"
#include "login_dialog.h"
#include "login_client.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // Uygulama özelliklerini ayarla
    app.setApplicationName("TacticalMapClient");
    app.setApplicationDisplayName("Tactical Data System");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("ONUR");
    
    // Uygulama ikonunu ayarla
    app.setWindowIcon(QIcon("ONUR_blue.png"));
    
    QQuickStyle::setStyle("Material");

    QString jwtToken;
    QString loginError;
    QString serverHost = "127.0.0.1";
    int serverPort = 8080;

    while (true) {
        LoginDialog loginDialog;
        if (loginDialog.exec() == QDialog::Accepted) {
            QString username = loginDialog.getUsername();
            QString password = loginDialog.getPassword();
            // Sunucuya bağlanıp login doğrulaması yap
            jwtToken = LoginClient::login(serverHost, serverPort, username, password, loginError);
            if (!jwtToken.isEmpty()) {
                MainWindow* window = new MainWindow();
                window->getClientWrapper()->setJwtToken(jwtToken);
                window->getClientWrapper()->connectToServer(serverHost, serverPort);
                window->show();

                QQmlApplicationEngine engine;
                engine.rootContext()->setContextProperty("mainWindow", window);
                engine.rootContext()->setContextProperty("clientWrapper", window->getClientWrapper());

                int result = app.exec();
                delete window;
                if (result == 12345) {
                    // Logout için özel kod, tekrar login ekranı göster
                    continue;
                }
                return result;
            } else {
                QMessageBox::warning(nullptr, "Giriş Hatası", loginError);
            }
        } else {
            return 0; // Kullanıcı iptal etti
        }
    }
    return 0;
}
