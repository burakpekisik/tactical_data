/**
 * @file mapwidget.cpp
 * @brief Client tarafı harita widget implementasyonu
 * @ingroup qt_client
 * 
 * QML harita bileşeni ile C++ arasında köprü sağlar.
 * Kullanıcı etkileşimi ve harita görselleştirmesi.
 */

#include "mapwidget.h"
#include <QQmlContext>
#include <QQmlEngine>
#include <QQuickItem>
#include <QDebug>

/**
 * @brief MapWidget constructor
 * @param parent Üst widget
 * @ingroup qt_client
 */
MapWidget::MapWidget(QWidget *parent)
    : QWidget(parent)
    , qmlWidget(nullptr)
    , layout(nullptr)
{
    setupQmlMap();
}

/**
 * @brief QML harita widget'ını kurar ve bağlar
 * @ingroup qt_client
 */
void MapWidget::setupQmlMap()
{
    layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    
    qmlWidget = new QQuickWidget(this);
    qmlWidget->setResizeMode(QQuickWidget::SizeRootObjectToView);
    
    // QML context'ine C++ nesnesini ve mod bilgisini kaydet
    qmlWidget->rootContext()->setContextProperty("mapWidget", this);
    qmlWidget->rootContext()->setContextProperty("mode", 0); // 0: SendMode, 1: ReplyMode (varsayılan SendMode)
    
    // QML dosyasını yükle
    qmlWidget->setSource(QUrl::fromLocalFile("map.qml"));
    
    if (qmlWidget->status() == QQuickWidget::Error) {
        qDebug() << "QML yükleme hatası:" << qmlWidget->errors();
    }
    
    layout->addWidget(qmlWidget);
    
    // QML'den gelen sinyalleri bağla
    QQuickItem *rootObject = qmlWidget->rootObject();
    if (rootObject) {
        connect(rootObject, SIGNAL(mapClicked(double, double)),
                this, SLOT(onQmlPointClicked(double, double)));
        connect(rootObject, SIGNAL(markerClicked(int, double, double)),
                this, SLOT(onQmlMarkerClicked(int, double, double)));
        connect(rootObject, SIGNAL(currentLocationMarkerClicked(double, double)),
                this, SLOT(onQmlCurrentLocationMarkerClicked(double, double)));
    }
}

/**
 * @brief QML haritadan gelen tıklama olayını işler
 * @param latitude Enlem koordinatı
 * @param longitude Boylam koordinatı
 * @ingroup qt_client
 */
void MapWidget::onQmlPointClicked(double latitude, double longitude)
{
    qDebug() << "Harita tıklandı:" << latitude << longitude;
    logToConsole(QString("Harita tıklandı: %1 %2").arg(latitude).arg(longitude));
    emit pointClicked(latitude, longitude);
}

void MapWidget::onQmlMarkerClicked(int id, double latitude, double longitude)
{
    qDebug() << "Marker tıklandı:" << id << latitude << longitude;
    emit markerClicked(id, latitude, longitude);
}

void MapWidget::onQmlCurrentLocationMarkerClicked(double latitude, double longitude)
{
    qDebug() << "Current location marker tıklandı:" << latitude << longitude;
    logToConsole(QString("Mevcut konum marker seçildi: %1 %2").arg(latitude).arg(longitude));
    emit currentLocationMarkerClicked(latitude, longitude);
}

void MapWidget::addMarker(double latitude, double longitude, const QString& description, const QString& status, int id, qint64 timestamp, bool isTemporary)
{
    if (!qmlWidget) return;
    QVariant returnedValue;
    QMetaObject::invokeMethod(qmlWidget->rootObject(), "addMarker",
        Q_ARG(QVariant, latitude),
        Q_ARG(QVariant, longitude),
        Q_ARG(QVariant, description),
        Q_ARG(QVariant, status),
        Q_ARG(QVariant, id),
        Q_ARG(QVariant, timestamp),
        Q_ARG(QVariant, isTemporary)
    );
    // logToConsole(QString("addMarker çağrıldı: %1, %2, %3, %4, %5, %6, %7")
    //     .arg(latitude).arg(longitude).arg(description).arg(status).arg(id).arg(timestamp).arg(isTemporary));
}

void MapWidget::clearMapItems()
{
    if (!qmlWidget) return;
    QMetaObject::invokeMethod(qmlWidget->rootObject(), "clearMapItems");
    logToConsole("clearMapItems çağrıldı");
}

void MapWidget::setMarkersVisible(bool visible)
{
    if (!qmlWidget) return;
    QMetaObject::invokeMethod(qmlWidget->rootObject(), "setMarkersVisible", Q_ARG(QVariant, visible));
    logToConsole(QString("setMarkersVisible çağrıldı: %1").arg(visible));
}

void MapWidget::setMode(int modeValue)
{
    if (qmlWidget) {
        qmlWidget->rootContext()->setContextProperty("mode", modeValue);
        // QML tarafında property güncellensin diye aşağıdaki satırı ekleyin:
        QMetaObject::invokeMethod(qmlWidget->rootObject(), "setMode");
    }
}

void MapWidget::setCurrentLocation(double latitude, double longitude)
{
    if (!qmlWidget) return;
    QMetaObject::invokeMethod(qmlWidget->rootObject(), "setCurrentLocation",
        Q_ARG(QVariant, latitude),
        Q_ARG(QVariant, longitude));
    logToConsole(QString("setCurrentLocation çağrıldı: %1, %2").arg(latitude).arg(longitude));
}

void MapWidget::applyFilters(const QString& dataTypeFilter, const QString& replyStatusFilter, const QString& timeFilter)
{
    if (!qmlWidget) return;
    QMetaObject::invokeMethod(qmlWidget->rootObject(), "applyFilters",
        Q_ARG(QVariant, dataTypeFilter),
        Q_ARG(QVariant, replyStatusFilter),
        Q_ARG(QVariant, timeFilter));
    logToConsole(QString("applyFilters çağrıldı: %1, %2, %3").arg(dataTypeFilter).arg(replyStatusFilter).arg(timeFilter));
}

void MapWidget::clearFilters()
{
    if (!qmlWidget) return;
    QMetaObject::invokeMethod(qmlWidget->rootObject(), "clearFilters");
    logToConsole("clearFilters çağrıldı");
}

void MapWidget::setReplyIdList(const QVariantList& idList)
{
    if (!qmlWidget) return;
    QMetaObject::invokeMethod(qmlWidget->rootObject(), "setReplyIdList",
        Q_ARG(QVariant, idList));
    logToConsole("setReplyIdList çağrıldı");
}

/**
 * @brief Haritayı belirtilen konuma odaklar ve zoom yapar
 * @param latitude Enlem koordinatı
 * @param longitude Boylam koordinatı
 * @details QML harita bileşenini belirtilen koordinatlara zoom yapar.
 *          Bildirim dialog'undan gelen konum istekleri için kullanılır.
 */
void MapWidget::centerOnLocation(double latitude, double longitude)
{
    if (!qmlWidget) {
        logToConsole("centerOnLocation: qmlWidget null!");
        return;
    }
    
    QObject *rootObject = qmlWidget->rootObject();
    if (!rootObject) {
        logToConsole("centerOnLocation: rootObject null!");
        return;
    }
    
    // QML harita bileşenine konumu merkeze alma ve zoom yapma talimatı ver
    QMetaObject::invokeMethod(rootObject, "centerOnLocation",
        Q_ARG(QVariant, latitude),
        Q_ARG(QVariant, longitude));
    
    logToConsole(QString("centerOnLocation çağrıldı: [%1, %2]")
                .arg(latitude, 0, 'f', 6)
                .arg(longitude, 0, 'f', 6));
}
