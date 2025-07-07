#ifndef MAPWIDGET_H
#define MAPWIDGET_H

#include <QWidget>
#include <QQuickWidget>
#include <QVBoxLayout>
#include <QQmlContext>
#include <QQmlEngine>
#include <QDebug>

class MapWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MapWidget(QWidget *parent = nullptr);
    Q_INVOKABLE void addMarker(double latitude, double longitude, const QString& description, const QString& status, int id, qint64 timestamp, bool isTemporary = false);
    Q_INVOKABLE void clearMapItems();
    Q_INVOKABLE void setMarkersVisible(bool visible);
    Q_INVOKABLE void setMode(int modeValue);
    Q_INVOKABLE void setCurrentLocation(double latitude, double longitude);
    Q_INVOKABLE void applyFilters(const QString& dataTypeFilter, const QString& replyStatusFilter, const QString& timeFilter);
    Q_INVOKABLE void clearFilters();
    Q_INVOKABLE void setReplyIdList(const QVariantList& idList);
    Q_INVOKABLE void centerOnLocation(double latitude, double longitude);

signals:
    void pointClicked(double latitude, double longitude);
    void markerClicked(int id, double latitude, double longitude);
    void currentLocationMarkerClicked(double latitude, double longitude);

private slots:
    void onQmlPointClicked(double latitude, double longitude);
    void onQmlMarkerClicked(int id, double latitude, double longitude);
    void onQmlCurrentLocationMarkerClicked(double latitude, double longitude);

private:
    void setupQmlMap();
    void logToConsole(const QString& msg) const { qDebug() << "[MapWidget]" << msg; }

    QQuickWidget *qmlWidget;
    QVBoxLayout *layout;
};

#endif // MAPWIDGET_H
