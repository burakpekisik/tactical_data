#include "login_dialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>

LoginDialog::LoginDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Giriş Yap");
    setModal(true);
    setFixedSize(350, 220);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QLabel *titleLabel = new QLabel("<b>Tactical Data Client</b>", this);
    titleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(titleLabel);

    QLabel *subtitleLabel = new QLabel("Harita Arayüzü Sistemi", this);
    subtitleLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(subtitleLabel);

    mainLayout->addSpacing(10);

    usernameEdit = new QLineEdit(this);
    usernameEdit->setPlaceholderText("Kullanıcı Adı");
    mainLayout->addWidget(usernameEdit);

    passwordEdit = new QLineEdit(this);
    passwordEdit->setPlaceholderText("Şifre");
    passwordEdit->setEchoMode(QLineEdit::Password);
    mainLayout->addWidget(passwordEdit);

    rememberCheckBox = new QCheckBox("Beni hatırla", this);
    mainLayout->addWidget(rememberCheckBox);

    errorLabel = new QLabel(this);
    errorLabel->setStyleSheet("color: red;");
    errorLabel->setVisible(false);
    mainLayout->addWidget(errorLabel);

    loginButton = new QPushButton("Giriş Yap", this);
    mainLayout->addWidget(loginButton);

    connect(loginButton, &QPushButton::clicked, this, &LoginDialog::onLoginClicked);
    connect(usernameEdit, &QLineEdit::returnPressed, this, &LoginDialog::onLoginClicked);
    connect(passwordEdit, &QLineEdit::returnPressed, this, &LoginDialog::onLoginClicked);
}

QString LoginDialog::getUsername() const {
    return usernameEdit->text().trimmed();
}

QString LoginDialog::getPassword() const {
    return passwordEdit->text();
}

bool LoginDialog::rememberMe() const {
    return rememberCheckBox->isChecked();
}

void LoginDialog::onLoginClicked() {
    errorLabel->setVisible(false);
    if (getUsername().isEmpty()) {
        errorLabel->setText("Kullanıcı adı boş olamaz!");
        errorLabel->setVisible(true);
        return;
    }
    if (getPassword().isEmpty()) {
        errorLabel->setText("Şifre boş olamaz!");
        errorLabel->setVisible(true);
        return;
    }
    accept();
}
