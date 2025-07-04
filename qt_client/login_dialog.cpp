#include "login_dialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QPixmap>
#include <QFrame>
#include <QApplication>
#include <QDir>

LoginDialog::LoginDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Tactical Data System - Giriş");
    setWindowIcon(QIcon("ONUR_blue.png"));
    setModal(true);
    setFixedSize(500, 650);
    
    // Ana mavi arka plan
    setStyleSheet("QDialog { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
                  "stop:0 #2E5BBA, stop:1 #1E3F7A); }");

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(50, 50, 50, 50);
    mainLayout->setSpacing(20);

    // Logo
    logoLabel = new QLabel(this);
    QPixmap logoPixmap("ONUR.png");
    if (!logoPixmap.isNull()) {
        logoPixmap = logoPixmap.scaled(150, 100, Qt::KeepAspectRatio, Qt::SmoothTransformation);
        logoLabel->setPixmap(logoPixmap);
    } else {
        logoLabel->setText("ONUR");
        logoLabel->setStyleSheet("color: white; font-size: 24px; font-weight: bold;");
    }
    logoLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(logoLabel);

    // Ana başlık
    QLabel *titleLabel = new QLabel("Tactical Data System", this);
    titleLabel->setAlignment(Qt::AlignCenter);
    titleLabel->setStyleSheet("color: white; font-size: 28px; font-weight: bold; margin: 10px;");
    mainLayout->addWidget(titleLabel);

    // Alt başlık
    QLabel *subtitleLabel = new QLabel("Harita Arayüzü Sistemi", this);
    subtitleLabel->setAlignment(Qt::AlignCenter);
    subtitleLabel->setStyleSheet("color: white; font-size: 16px; margin-bottom: 20px;");
    mainLayout->addWidget(subtitleLabel);

    // Beyaz form çerçevesi
    formFrame = new QFrame(this);
    formFrame->setStyleSheet("QFrame { background-color: white; border-radius: 15px; padding: 20px; }");
    formFrame->setFixedHeight(280);
    
    QVBoxLayout *formLayout = new QVBoxLayout(formFrame);
    formLayout->setContentsMargins(30, 30, 30, 30);
    formLayout->setSpacing(15);

    // Kullanıcı adı alanı
    usernameEdit = new QLineEdit(this);
    usernameEdit->setPlaceholderText("👤 Kullanıcı Adı");
    usernameEdit->setStyleSheet("QLineEdit { border: 2px solid #ddd; border-radius: 8px; "
                               "padding: 12px 15px; font-size: 14px; } "
                               "QLineEdit:focus { border-color: #2E5BBA; }");
    usernameEdit->setMinimumHeight(45);
    formLayout->addWidget(usernameEdit);

    // Şifre alanı - container ile göz ikonu
    QWidget *passwordContainer = new QWidget(this);
    passwordContainer->setStyleSheet("QWidget { border: 2px solid #ddd; border-radius: 8px; background-color: white; } "
                                   "QWidget:focus-within { border-color: #2E5BBA; }");
    passwordContainer->setMinimumHeight(45);
    
    QHBoxLayout *passwordLayout = new QHBoxLayout(passwordContainer);
    passwordLayout->setContentsMargins(15, 0, 10, 0);
    passwordLayout->setSpacing(5);
    
    passwordEdit = new QLineEdit(passwordContainer);
    passwordEdit->setPlaceholderText("🔒 Şifre");
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setStyleSheet("QLineEdit { border: none; font-size: 14px; background: transparent; } "
                               "QLineEdit:focus { border: none; }");
    
    togglePasswordButton = new QPushButton("👁", passwordContainer);
    togglePasswordButton->setStyleSheet("QPushButton { border: none; background: transparent; "
                                       "font-size: 16px; padding: 5px; } "
                                       "QPushButton:hover { background-color: #f0f0f0; border-radius: 3px; }");
    togglePasswordButton->setFixedSize(30, 30);
    togglePasswordButton->setToolTip("Şifreyi göster/gizle");
    
    passwordLayout->addWidget(passwordEdit);
    passwordLayout->addWidget(togglePasswordButton);
    
    formLayout->addWidget(passwordContainer);

    // Beni hatırla checkbox - sol tarafta hizalı
    QHBoxLayout *checkboxLayout = new QHBoxLayout();
    rememberCheckBox = new QCheckBox("Beni hatırla", this);
    rememberCheckBox->setStyleSheet("QCheckBox { color: #666; font-size: 12px; margin: 5px 0; }");
    checkboxLayout->addWidget(rememberCheckBox);
    checkboxLayout->addStretch(); // Sağ tarafı boş bırak
    formLayout->addLayout(checkboxLayout);

    // Hata mesajı
    errorLabel = new QLabel(this);
    errorLabel->setStyleSheet("color: red; font-size: 12px;");
    errorLabel->setVisible(false);
    formLayout->addWidget(errorLabel);

    // Giriş butonu
    loginButton = new QPushButton("Giriş Yap", this);
    loginButton->setStyleSheet("QPushButton { background-color: #2E5BBA; color: white; "
                              "border: none; border-radius: 8px; padding: 15px; "
                              "font-size: 16px; font-weight: bold; } "
                              "QPushButton:hover { background-color: #1E3F7A; } "
                              "QPushButton:pressed { background-color: #0F2850; }");
    loginButton->setMinimumHeight(50);
    formLayout->addWidget(loginButton);

    mainLayout->addWidget(formFrame);
    mainLayout->addStretch();

    connect(loginButton, &QPushButton::clicked, this, &LoginDialog::onLoginClicked);
    connect(usernameEdit, &QLineEdit::returnPressed, this, &LoginDialog::onLoginClicked);
    connect(passwordEdit, &QLineEdit::returnPressed, this, &LoginDialog::onLoginClicked);
    connect(togglePasswordButton, &QPushButton::clicked, this, &LoginDialog::togglePasswordVisibility);
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

void LoginDialog::togglePasswordVisibility() {
    if (passwordEdit->echoMode() == QLineEdit::Password) {
        passwordEdit->setEchoMode(QLineEdit::Normal);
        togglePasswordButton->setText("🙈");
        togglePasswordButton->setToolTip("Şifreyi gizle");
    } else {
        passwordEdit->setEchoMode(QLineEdit::Password);
        togglePasswordButton->setText("👁");
        togglePasswordButton->setToolTip("Şifreyi göster");
    }
}
