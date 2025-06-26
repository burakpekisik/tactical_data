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

signals:
    void pointClicked(double latitude, double longitude);

private slots:
    void onQmlPointClicked(double latitude, double longitude);

private:
    void setupQmlMap();
    void logToConsole(const QString& msg) const { qDebug() << "[MapWidget]" << msg; }

    QQuickWidget *qmlWidget;
    QVBoxLayout *layout;
};

#endif // MAPWIDGET_H
