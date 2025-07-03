/**
 * @file notification_dialog.h
 * @brief Admin bildirim dialog'u sınıfı
 * @details Bu dosya admin bildirimlerini görsel olarak gösteren dialog sınıfını içerir.
 *          Bildirim detaylarını gösterir, konuma zoom yapma ve cevap verme özelliği sağlar.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 */

#ifndef NOTIFICATION_DIALOG_H
#define NOTIFICATION_DIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTextEdit>
#include <QPushButton>
#include <QFrame>
#include <QScrollArea>
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QTimer>
#include <QPropertyAnimation>
#include <QGraphicsEffect>
#include <QGraphicsDropShadowEffect>
#include <QApplication>
#include <QScreen>

/**
 * @brief Admin bildirim dialog'u sınıfı
 * @details Admin bildirimlerini estetik ve kullanışlı bir dialog ile gösterir.
 *          Bildirim detaylarını, konuma zoom yapma ve cevap verme seçeneklerini sağlar.
 */
class NotificationDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief NotificationDialog constructor'ı
     * @param notification Bildirim JSON metni
     * @param parent Üst widget
     */
    explicit NotificationDialog(const QString& notification, QWidget *parent = nullptr);
    
    /**
     * @brief Dialog'u güzel bir animasyonla gösterir
     */
    void showWithAnimation();

signals:
    /**
     * @brief Konuma zoom yapma isteği signal'ı
     * @param latitude Enlem koordinatı
     * @param longitude Boylam koordinatı
     */
    void zoomToLocation(double latitude, double longitude);
    
    /**
     * @brief Rapora cevap verme isteği signal'ı
     * @param reportId Rapor ID'si
     * @param initialMessage Önceden doldurulacak mesaj (opsiyonel)
     */
    void replyToReport(int reportId, const QString& initialMessage = "");
    
    /**
     * @brief Dialog kapatma signal'ı
     */
    void dialogClosed();

private slots:
    /**
     * @brief Konuma git butonu tıklandığında çağrılır
     */
    void onGoToLocation();
    
    /**
     * @brief Cevap ver butonu tıklandığında çağrılır
     */
    void onReplyToReport();
    
    /**
     * @brief Kapat butonu tıklandığında çağrılır
     */
    void onCloseDialog();

private:
    /**
     * @brief UI bileşenlerini kurar
     */
    void setupUI();
    
    /**
     * @brief Dialog stilini ayarlar
     */
    void setupStyling();
    
    /**
     * @brief Gölge efekti ekler
     */
    void setupShadowEffect();
    
    /**
     * @brief Bildirim JSON'ını parse eder
     * @param notification JSON string
     * @return Parse edilen QJsonObject
     */
    QJsonObject parseNotification(const QString& notification);
    
    /**
     * @brief Bildirim tipine göre ikon döndürür
     * @param type Bildirim tipi
     * @return Ikon metni (emoji veya karakter)
     */
    QString getNotificationIcon(const QString& type);
    
    /**
     * @brief Bildirim tipine göre renk döndürür
     * @param type Bildirim tipi
     * @return CSS renk kodu
     */
    QString getNotificationColor(const QString& type);

private:
    // UI bileşenleri
    QVBoxLayout *mainLayout;
    QLabel *titleLabel;
    QLabel *iconLabel;
    QTextEdit *detailsTextEdit;
    QFrame *buttonFrame;
    QHBoxLayout *buttonLayout;
    QPushButton *goToLocationButton;
    QPushButton *replyButton;
    QPushButton *closeButton;
    
    // Veri
    QJsonObject notificationData;
    double latitude;
    double longitude;
    int reportId;
    QString reportType;
    QString reportMessage;
    QString timestamp;
    QString userId;
    QString userStatus;
    
    // Animasyon
    QPropertyAnimation *showAnimation;
    QTimer *autoCloseTimer;
    
    // Durum
    bool hasValidLocation;
    bool hasValidReportId;
};

#endif // NOTIFICATION_DIALOG_H
