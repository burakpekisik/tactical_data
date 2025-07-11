/**
 * @file notification_dialog.cpp
 * @brief Admin bildirim dialog'u implementasyonu
 * @details Bu dosya admin bildirimlerini görsel olarak gösteren dialog sınıfının
 *          implementasyonunu içerir. Modern UI tasarımı ve animasyonlar sağlar.
 * @author Tactical Data Transfer System
 * @date 2025
 * @version 1.0
 */

#include "notification_dialog.h"
#include <QDebug>
#include <QFont>
#include <QFontMetrics>
#include <QDateTime>
#include <QRegularExpression>
#include <QGuiApplication>

static bool supportsWindowOpacity() {
#if defined(Q_OS_WIN)
    return true;
#else
    QString platform = QGuiApplication::platformName();
    return (platform == "xcb" || platform == "windows" || platform == "cocoa");
#endif
}

/**
 * @brief NotificationDialog constructor'ı
 * @param notification Bildirim JSON metni
 * @param parent Üst widget
 */
NotificationDialog::NotificationDialog(const QString& notification, QWidget *parent)
    : QDialog(parent)
    , mainLayout(nullptr)
    , titleLabel(nullptr)
    , iconLabel(nullptr)
    , detailsTextEdit(nullptr)
    , buttonFrame(nullptr)
    , buttonLayout(nullptr)
    , goToLocationButton(nullptr)
    , replyButton(nullptr)
    , closeButton(nullptr)
    , latitude(0.0)
    , longitude(0.0)
    , reportId(-1)
    , showAnimation(nullptr)
    , autoCloseTimer(nullptr)
    , hasValidLocation(false)
    , hasValidReportId(false)
    , userId("")
    , userStatus("")
{
    // JSON bildirimini parse et
    notificationData = parseNotification(notification);
    
    // Veriyi extract et
    if (notificationData.contains("latitude") && notificationData.contains("longitude")) {
        latitude = notificationData["latitude"].toDouble();
        longitude = notificationData["longitude"].toDouble();
        hasValidLocation = true;
    }
    
    if (notificationData.contains("report_id")) {
        reportId = notificationData["report_id"].toInt();
        hasValidReportId = (reportId > 0);
    }
    
    if (notificationData.contains("type")) {
        reportType = notificationData["type"].toString();
    } else if (notificationData.contains("status")) {
        reportType = notificationData["status"].toString();
    }
    
    if (notificationData.contains("message")) {
        reportMessage = notificationData["message"].toString();
    } else if (notificationData.contains("description")) {
        reportMessage = notificationData["description"].toString();
    }
    
    if (notificationData.contains("timestamp")) {
        timestamp = notificationData["timestamp"].toString();
    }
    
    // Ek bilgileri al
    if (notificationData.contains("user_id")) {
        userId = notificationData["user_id"].toString();
    }
    
    if (notificationData.contains("status")) {
        userStatus = notificationData["status"].toString();
    }
    
    setupUI();
    setupStyling();
    setupShadowEffect();
    
    // Dialog özelliklerini ayarla
    setModal(false); // Modal olmayan dialog (arkaplanda çalışmaya devam edebilsin)
    setWindowFlags(Qt::Dialog | Qt::WindowStaysOnTopHint | Qt::WindowCloseButtonHint);
    setWindowTitle("🚨 Admin Bildirimi");
    
    // Otomatik kapatma timer'ı (30 saniye)
    autoCloseTimer = new QTimer(this);
    autoCloseTimer->setSingleShot(true);
    autoCloseTimer->setInterval(30000); // 30 saniye
    connect(autoCloseTimer, &QTimer::timeout, this, &NotificationDialog::onCloseDialog);
}

/**
 * @brief Dialog'u güzel bir animasyonla gösterir
 */
void NotificationDialog::showWithAnimation()
{
    // Ekranın merkezine konumlandır
    QScreen *screen = QApplication::primaryScreen();
    if (screen) {
        QRect screenGeometry = screen->geometry();
        int x = (screenGeometry.width() - width()) / 2;
        int y = (screenGeometry.height() - height()) / 2;
        move(x, y);
    }

    if (supportsWindowOpacity()) {
        setWindowOpacity(0.0);
        show();
        // Fade-in animasyonu
        showAnimation = new QPropertyAnimation(this, "windowOpacity", this);
        showAnimation->setDuration(500);
        showAnimation->setStartValue(0.0);
        showAnimation->setEndValue(1.0);
        showAnimation->setEasingCurve(QEasingCurve::OutCubic);
        showAnimation->start();
    } else {
        show();
    }

    // Otomatik kapatma timer'ını başlat
    autoCloseTimer->start();
    QApplication::beep();
}

/**
 * @brief UI bileşenlerini kurar
 */
void NotificationDialog::setupUI()
{
    mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    
    // Başlık ve ikon satırı
    QHBoxLayout *headerLayout = new QHBoxLayout();
    
    // Bildirim ikonu (JSON'dan override edilebilir)
    iconLabel = new QLabel();
    iconLabel->setFixedSize(48, 48);
    iconLabel->setAlignment(Qt::AlignCenter);
    QString customIcon, customColor;
    if (notificationData.contains("icon")) customIcon = notificationData["icon"].toString();
    if (notificationData.contains("color")) customColor = notificationData["color"].toString();
    if (!customIcon.isEmpty()) {
        iconLabel->setText(customIcon);
    } else {
        iconLabel->setText(getNotificationIcon(reportType));
    }
    iconLabel->setStyleSheet(QString(
        "QLabel {"
        "    font-size: 32px;"
        "    color: %1;"
        "    background: transparent;"
        "    border: none;"
        "}"
    ).arg(!customColor.isEmpty() ? customColor : getNotificationColor(reportType)));
    
    // Başlık metni
    titleLabel = new QLabel();
    titleLabel->setWordWrap(true);
    QString customTitle;
    if (notificationData.contains("title")) {
        customTitle = notificationData["title"].toString();
    }
    if (!customTitle.isEmpty()) {
        titleLabel->setText(QString("<b>%1</b>").arg(customTitle.toHtmlEscaped()));
    } else {
        titleLabel->setText(QString("🚨 <b>YENİ BİLDİRİM</b> - %1").arg(reportType.isEmpty() ? "Bilinmeyen" : reportType));
    }
    
    headerLayout->addWidget(iconLabel);
    headerLayout->addWidget(titleLabel, 1);
    headerLayout->addStretch();
    
    // Detay alanı
    detailsTextEdit = new QTextEdit();
    detailsTextEdit->setReadOnly(true);
    detailsTextEdit->setMaximumHeight(250);
    detailsTextEdit->setMinimumHeight(150);
    
    // Detay içeriğini oluştur
    QString detailsHtml = "<div style='line-height: 1.4;'>";
    
    // Kullanıcı ID'si varsa göster
    if (!userId.isEmpty()) {
        detailsHtml += QString("<p><b>👤 Kullanıcı ID:</b> %1</p>").arg(userId.toHtmlEscaped());
    }
    
    // Durum bilgisi varsa göster
    if (!userStatus.isEmpty()) {
        detailsHtml += QString("<p><b>� Durum:</b> %1</p>").arg(userStatus.toHtmlEscaped());
    }
    
    // Mesaj/açıklama varsa göster
    QString customMsg;
    if (notificationData.contains("message")) {
        customMsg = notificationData["message"].toString();
    }
    if (!customMsg.isEmpty()) {
        detailsHtml += QString("<p style='font-size:15px;'><b>%1</b></p>").arg(customMsg.toHtmlEscaped());
    } else if (!reportMessage.isEmpty()) {
        detailsHtml += QString("<p><b>📄 Açıklama:</b><br>%1</p>").arg(reportMessage.toHtmlEscaped());
    }
    
    // Rapor ID'si varsa göster
    if (hasValidReportId) {
        detailsHtml += QString("<p><b>📋 Rapor ID:</b> %1</p>").arg(reportId);
    }
    
    // Konum bilgisi varsa göster
    if (hasValidLocation) {
        detailsHtml += QString("<p><b>📍 Konum:</b><br>Enlem: %1<br>Boylam: %2</p>")
                          .arg(latitude, 0, 'f', 6)
                          .arg(longitude, 0, 'f', 6);
    }
    
    // Zaman bilgisi varsa göster
    if (!timestamp.isEmpty()) {
        // Unix timestamp olup olmadığını kontrol et
        bool isUnixTimestamp = false;
        qint64 unixTime = timestamp.toLongLong(&isUnixTimestamp);
        
        if (isUnixTimestamp && unixTime > 0) {
            // Unix timestamp'i QDateTime'a çevir
            QDateTime dt = QDateTime::fromSecsSinceEpoch(unixTime);
            detailsHtml += QString("<p><b>🕐 Zaman:</b> %1</p>").arg(dt.toString("dd.MM.yyyy hh:mm:ss"));
        } else {
            // ISO format veya başka format
            QDateTime dt = QDateTime::fromString(timestamp, Qt::ISODate);
            if (dt.isValid()) {
                detailsHtml += QString("<p><b>🕐 Zaman:</b> %1</p>").arg(dt.toString("dd.MM.yyyy hh:mm:ss"));
            } else {
                detailsHtml += QString("<p><b>🕐 Zaman:</b> %1</p>").arg(timestamp);
            }
        }
    }
    
    detailsHtml += "</div>";
    detailsTextEdit->setHtml(detailsHtml);
    
    // Buton çerçevesi
    buttonFrame = new QFrame();
    buttonLayout = new QHBoxLayout(buttonFrame);
    buttonLayout->setSpacing(10);
    
    // Konuma git butonu (sadece geçerli konum varsa)
    if (hasValidLocation) {
        goToLocationButton = new QPushButton("🎯 Konuma Git");
        goToLocationButton->setMinimumHeight(40);
        connect(goToLocationButton, &QPushButton::clicked, this, &NotificationDialog::onGoToLocation);
        buttonLayout->addWidget(goToLocationButton);
    }
    
    // Cevap ver butonu (sadece geçerli rapor ID varsa)
    if (hasValidReportId) {
        replyButton = new QPushButton("💬 Cevap Ver");
        replyButton->setMinimumHeight(40);
        connect(replyButton, &QPushButton::clicked, this, &NotificationDialog::onReplyToReport);
        buttonLayout->addWidget(replyButton);
    }
    
    // Kapat butonu
    closeButton = new QPushButton("❌ Kapat");
    closeButton->setMinimumHeight(40);
    connect(closeButton, &QPushButton::clicked, this, &NotificationDialog::onCloseDialog);
    buttonLayout->addWidget(closeButton);
    
    // Layout'a ekle
    mainLayout->addLayout(headerLayout);
    mainLayout->addWidget(detailsTextEdit);
    mainLayout->addWidget(buttonFrame);
    
    // Dialog boyutunu ayarla
    setFixedSize(420, 260);
}

/**
 * @brief Dialog stilini ayarlar
 */
void NotificationDialog::setupStyling()
{
    // Ana dialog stili
    setStyleSheet(
        "QDialog {"
        "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
        "                                stop:0 #ffffff, stop:1 #f8f9fa);"
        "    border: 2px solid #e9ecef;"
        "    border-radius: 15px;"
        "}"
        
        "QLabel {"
        "    color: #212529;"
        "    font-family: 'Segoe UI', Tahoma, Arial, sans-serif;"
        "    font-size: 14px;"
        "    background: transparent;"
        "    border: none;"
        "}"
        
        "QTextEdit {"
        "    border: 1px solid #dee2e6;"
        "    border-radius: 8px;"
        "    padding: 10px;"
        "    background: #ffffff;"
        "    font-family: 'Segoe UI', Tahoma, Arial, sans-serif;"
        "    font-size: 13px;"
        "    color: #495057;"
        "    selection-background-color: #007bff;"
        "}"
        
        "QPushButton {"
        "    border: 2px solid #007bff;"
        "    border-radius: 8px;"
        "    padding: 8px 16px;"
        "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
        "                                stop:0 #007bff, stop:1 #0056b3);"
        "    color: white;"
        "    font-family: 'Segoe UI', Tahoma, Arial, sans-serif;"
        "    font-size: 13px;"
        "    font-weight: bold;"
        "    min-width: 100px;"
        "}"
        
        "QPushButton:hover {"
        "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
        "                                stop:0 #0056b3, stop:1 #004085);"
        "    border-color: #0056b3;"
        "}"
        
        "QPushButton:pressed {"
        "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
        "                                stop:0 #004085, stop:1 #002752);"
        "    border-color: #004085;"
        "}"
        
        "QFrame {"
        "    background: transparent;"
        "    border: none;"
        "}"
    );
    
    // Başlık labelını özel stillendir
    if (titleLabel) {
        titleLabel->setStyleSheet(
            "QLabel {"
            "    font-size: 16px;"
            "    font-weight: bold;"
            "    color: #212529;"
            "    padding: 5px;"
            "}"
        );
    }
    
    // Butonları özel stillendir
    if (goToLocationButton) {
        goToLocationButton->setStyleSheet(
            "QPushButton {"
            "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
            "                                stop:0 #28a745, stop:1 #1e7e34);"
            "    border-color: #28a745;"
            "}"
            "QPushButton:hover {"
            "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
            "                                stop:0 #1e7e34, stop:1 #155724);"
            "    border-color: #1e7e34;"
            "}"
        );
    }
    
    if (replyButton) {
        replyButton->setStyleSheet(
            "QPushButton {"
            "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
            "                                stop:0 #17a2b8, stop:1 #117a8b);"
            "    border-color: #17a2b8;"
            "}"
            "QPushButton:hover {"
            "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
            "                                stop:0 #117a8b, stop:1 #0c5460);"
            "    border-color: #117a8b;"
            "}"
        );
    }
    
    if (closeButton) {
        closeButton->setStyleSheet(
            "QPushButton {"
            "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
            "                                stop:0 #dc3545, stop:1 #bd2130);"
            "    border-color: #dc3545;"
            "}"
            "QPushButton:hover {"
            "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
            "                                stop:0 #bd2130, stop:1 #a71e2a);"
            "    border-color: #bd2130;"
            "}"
        );
    }
}

/**
 * @brief Gölge efekti ekler
 */
void NotificationDialog::setupShadowEffect()
{
    QGraphicsDropShadowEffect *shadowEffect = new QGraphicsDropShadowEffect();
    shadowEffect->setBlurRadius(20);
    shadowEffect->setColor(QColor(0, 0, 0, 60));
    shadowEffect->setOffset(0, 5);
    setGraphicsEffect(shadowEffect);
}

/**
 * @brief Bildirim JSON'ını parse eder
 * @param notification JSON string
 * @return Parse edilen QJsonObject
 */
QJsonObject NotificationDialog::parseNotification(const QString& notification)
{
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(notification.toUtf8(), &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        qDebug() << "[NotificationDialog] JSON parse hatası:" << parseError.errorString();
        
        // Basit text parsing fallback (JSON değilse)
        QJsonObject fallbackObj;
        fallbackObj["message"] = notification;
        fallbackObj["type"] = "Bildirim";
        fallbackObj["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        return fallbackObj;
    }
    
    return doc.object();
}

/**
 * @brief Bildirim tipine göre ikon döndürür
 * @param type Bildirim tipi
 * @return Ikon metni (emoji veya karakter)
 */
QString NotificationDialog::getNotificationIcon(const QString& type)
{
    QString lowerType = type.toLower();
    
    if (lowerType.contains("emergency") || lowerType.contains("acil")) {
        return "🆘";
    } else if (lowerType.contains("warning") || lowerType.contains("uyarı")) {
        return "⚠️";
    } else if (lowerType.contains("info") || lowerType.contains("bilgi")) {
        return "ℹ️";
    } else if (lowerType.contains("tactical") || lowerType.contains("taktik")) {
        return "🎯";
    } else if (lowerType.contains("location") || lowerType.contains("konum")) {
        return "📍";
    } else if (lowerType.contains("report") || lowerType.contains("rapor")) {
        return "📋";
    } else {
        return "🚨";
    }
}

/**
 * @brief Bildirim tipine göre renk döndürür
 * @param type Bildirim tipi
 * @return CSS renk kodu
 */
QString NotificationDialog::getNotificationColor(const QString& type)
{
    QString lowerType = type.toLower();
    
    if (lowerType.contains("emergency") || lowerType.contains("acil")) {
        return "#dc3545"; // Kırmızı
    } else if (lowerType.contains("warning") || lowerType.contains("uyarı")) {
        return "#ffc107"; // Sarı
    } else if (lowerType.contains("info") || lowerType.contains("bilgi")) {
        return "#17a2b8"; // Mavi
    } else if (lowerType.contains("tactical") || lowerType.contains("taktik")) {
        return "#28a745"; // Yeşil
    } else {
        return "#6c757d"; // Gri
    }
}

/**
 * @brief Konuma git butonu tıklandığında çağrılır
 */
void NotificationDialog::onGoToLocation()
{
    if (hasValidLocation) {
        emit zoomToLocation(latitude, longitude);
        onCloseDialog(); // Dialog'u kapat
    }
}

/**
 * @brief Cevap ver butonu tıklandığında çağrılır
 */
void NotificationDialog::onReplyToReport()
{
    if (hasValidReportId) {
        QString initialMessage = QString("Rapor #%1 hakkında: ").arg(reportId);
        emit replyToReport(reportId, initialMessage);
        onCloseDialog(); // Dialog'u kapat
    }
}

/**
 * @brief Kapat butonu tıklandığında çağrılır
 */
void NotificationDialog::onCloseDialog()
{
    // Timer'ı durdur
    if (autoCloseTimer && autoCloseTimer->isActive()) {
        autoCloseTimer->stop();
    }
    emit dialogClosed();
    if (supportsWindowOpacity() && showAnimation) {
        showAnimation->stop();
        QPropertyAnimation *closeAnimation = new QPropertyAnimation(this, "windowOpacity", this);
        closeAnimation->setDuration(300);
        closeAnimation->setStartValue(windowOpacity());
        closeAnimation->setEndValue(0.0);
        closeAnimation->setEasingCurve(QEasingCurve::InCubic);
        connect(closeAnimation, &QPropertyAnimation::finished, this, &QDialog::close);
        closeAnimation->start();
    } else {
        close();
    }
}
