#ifndef FALLBACK_TEST_THREAD_H
#define FALLBACK_TEST_THREAD_H

#include <QThread>
#include <QString>

class FallbackTestThread : public QThread {
    Q_OBJECT
public:
    FallbackTestThread(const QString& host, int port, QObject* parent = nullptr);

signals:
    void fallbackTestResult(const QString& type, bool success, const QString& message);
    void allTestsFinished();

protected:
    void run() override;

private:
    QString host;
    int port;
    bool testTcp();
    bool testUdp();
    bool testP2p();
};

#endif // FALLBACK_TEST_THREAD_H
