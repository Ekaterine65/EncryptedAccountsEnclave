#include "credentialwidget.h"
#include "ui_credentialwidget.h"

credentialwidget::credentialwidget(const QString &site, const int id, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::credentialwidget)
{
    m_id = id;

    ui->setupUi(this);
    QPixmap pix("../lab1/images/padlock1.bmp");
    ui->icon->setPixmap(pix);
    ui->label->setText(site);
    ui->loginText->setText("login");
    ui->passwordText->setText("password");

}

credentialwidget::~credentialwidget()
{
    delete ui;
}

void credentialwidget::on_copyLog_clicked()
{
    qDebug() << "*** Pressed " << m_id;
    emit decryptLoginPassword(m_id, FIELD::LOGIN);
}



void credentialwidget::on_copyPass_clicked()
{
    qDebug() << "*** Pressed " << m_id;
    emit decryptLoginPassword(m_id, FIELD::PASSWORD);
}

