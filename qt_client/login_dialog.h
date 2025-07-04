#ifndef LOGIN_DIALOG_H
#define LOGIN_DIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QPixmap>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QIcon>

class LoginDialog : public QDialog {
    Q_OBJECT
public:
    explicit LoginDialog(QWidget *parent = nullptr);
    QString getUsername() const;
    QString getPassword() const;
    bool rememberMe() const;

private:
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QPushButton *loginButton;
    QLabel *errorLabel;
    QCheckBox *rememberCheckBox;
    QLabel *logoLabel;
    QFrame *formFrame;
    QPushButton *togglePasswordButton;

private slots:
    void onLoginClicked();
    void togglePasswordVisibility();
};

#endif // LOGIN_DIALOG_H
