/**
 * @file servermapwidget.cpp
 * @brief Server tarafı harita widget implementasyonu
 * @ingroup qt_server
 * 
 * QML harita bileşeni ile C++ arasında veri köprüsü sağlar.
 * Taktik verilerin server haritasında görselleştirilmesi.
 */

#include "servermapwidget.h"
#include <QUrl>
#include <QQmlContext>
#include <QQuickItem>

/**
 * @brief ServerMapWidget constructor
 * @param parent Üst widget
 * @ingroup qt_server
 */
ServerMapWidget::ServerMapWidget(QWidget *parent)
    : QWidget(parent)
    , qmlWidget(nullptr)
{
    setupQmlWidget();
}

/**
 * @brief QML harita widget'ını kurar ve bağlar
 * @ingroup qt_server
 */
void ServerMapWidget::setupQmlWidget()
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    
    qmlWidget = new QQuickWidget(this);
    qmlWidget->setSource(QUrl::fromLocalFile("servermap.qml"));
    qmlWidget->setResizeMode(QQuickWidget::SizeRootObjectToView);
    
    layout->addWidget(qmlWidget);
    
    // QML context'e C++ nesnesini expose et
    QQmlContext *context = qmlWidget->rootContext();
    context->setContextProperty("serverMapWidget", this);
}

/**
 * @brief Server haritasına yeni marker ekler
 * @param latitude Enlem koordinatı
 * @param longitude Boylam koordinatı
 * @param dataType Veri türü
 * @param message Marker mesajı
 * @ingroup qt_server
 */
void ServerMapWidget::addMarker(double latitude, double longitude, const QString &dataType, const QString &message)
{
    // QML'e marker ekleme sinyali gönder
    emit markerAdded(latitude, longitude, dataType, message);
    
    // QML metodunu çağır - QQuickItem'ı QObject*'e static cast et
    if (qmlWidget && qmlWidget->rootObject()) {
        QObject *rootObj = static_cast<QObject*>(qmlWidget->rootObject());
        QMetaObject::invokeMethod(rootObj, "addServerMarker",
                                Qt::QueuedConnection,
                                Q_ARG(QVariant, latitude),
                                Q_ARG(QVariant, longitude),
                                Q_ARG(QVariant, dataType),
                                Q_ARG(QVariant, message));
    }
}

/**
 * @brief Haritadaki tüm marker'ları temizler
 * @ingroup qt_server
 */
void ServerMapWidget::clearMarkers()
{
    // QML metodunu çağır - QQuickItem'ı QObject*'e static cast et
    if (qmlWidget && qmlWidget->rootObject()) {
        QObject *rootObj = static_cast<QObject*>(qmlWidget->rootObject());
        QMetaObject::invokeMethod(rootObj, "clearAllMarkers",
                                Qt::QueuedConnection);
    }
}
