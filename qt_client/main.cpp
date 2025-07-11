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
                // Modern notification dialog ile göster
                QString notifType, notifIcon, notifColor, notifTitle, notifDetail;
                if (loginError.contains("bağlanılamadı", Qt::CaseInsensitive)) {
                    notifType = "connection";
                    notifIcon = "🌐";
                    notifColor = "#dc3545";
                    notifTitle = "Sunucuya Bağlanılamadı";
                    notifDetail = "Sunucuya ulaşılamadı. Lütfen ağ bağlantınızı ve sunucu adresini kontrol edin.";
                } else if (loginError.contains("kullanıcı adı") || loginError.contains("şifre") || loginError.contains("hatalı")) {
                    notifType = "login";
                    notifIcon = "🔒";
                    notifColor = "#ffc107";
                    notifTitle = "Giriş Bilgileri Hatalı";
                    notifDetail = "Kullanıcı adı veya şifre yanlış. Lütfen tekrar deneyin.";
                } else {
                    notifType = "error";
                    notifIcon = "❗";
                    notifColor = "#6c757d";
                    notifTitle = "Giriş Hatası";
                    notifDetail = loginError;
                }
                NotificationDialog* notif = new NotificationDialog("", nullptr);
                notif->setWindowTitle(notifTitle);
                notif->setCustomNotification(notifTitle, notifIcon, notifDetail);
                notif->showWithAnimation();
                // Modal gibi davran, kullanıcı kapatana kadar bekle
                while (notif->isVisible()) {
                    app.processEvents(QEventLoop::AllEvents, 100);
                }
                delete notif;
            }
        } else {
            return 0; // Kullanıcı iptal etti
        }
    }
    return 0;
}
