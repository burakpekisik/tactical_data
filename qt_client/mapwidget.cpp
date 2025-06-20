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
    
    // QML context'ine C++ nesnesini kaydet
    qmlWidget->rootContext()->setContextProperty("mapWidget", this);
    
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
    emit pointClicked(latitude, longitude);
}
