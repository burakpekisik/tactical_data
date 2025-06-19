#ifndef MAPWIDGET_H
#define MAPWIDGET_H

#include <QWidget>
#include <QQuickWidget>
#include <QVBoxLayout>
#include <QQmlContext>
#include <QQmlEngine>

class MapWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MapWidget(QWidget *parent = nullptr);

signals:
    void pointClicked(double latitude, double longitude);

private slots:
    void onQmlPointClicked(double latitude, double longitude);

private:
    void setupQmlMap();
    
    QQuickWidget *qmlWidget;
    QVBoxLayout *layout;
};

#endif // MAPWIDGET_H
