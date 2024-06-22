#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QJsonArray>
#include <QMainWindow>
#include "credentialwidget.h"

#include <QLibrary>
#include <Windows.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

typedef void (WINAPI* t_accessPersonalData)(char* outbuf, const size_t len, const size_t i);
typedef void (WINAPI* t_setPersonalData)(char* inbuf, const size_t len, const size_t i);


class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool readJSON(const QByteArray &aes256_key);
    QByteArray showPinDialog();

private:
    Ui::MainWindow *ui;
    QJsonArray m_jsonarray; //структура данных, содержащая учетные данные
    int m_current_id = -1;
    bool m_field = 0;
    bool m_isStartup = true;

    QLibrary lib;
    t_accessPersonalData accessPersonalData = nullptr;
    t_setPersonalData setPersonalData = nullptr;
    bool loadLibrary();

public slots:
    int decryptFile(const QByteArray &aes256_key, const QByteArray &encryptedBytes, QByteArray &decryptedBytes);
    void filterList(const QString &text);

private slots:
    void on_editPin_returnPressed();
    void decryptLoginPassword(int id, credentialwidget::FIELD field);
};
#endif // MAINWINDOW_H
