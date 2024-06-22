#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "credentialwidget.h"

#include <QBuffer>
#include <QFile>
#include <QCryptographicHash>
#include <openssl/evp.h>
#include <QGuiApplication>
#include <QClipboard>

#include <QLibrary>
#include <Windows.h>

//typedef void (WINAPI* t_accessPersonalData)(char* outbuf, const size_t len, const size_t i);
//typedef void (WINAPI* t_setPersonalData)(char* inbuf, const size_t len, const size_t i);

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->lineEdit, &QLineEdit::textEdited, this, &MainWindow::filterList);

    if (!loadLibrary()) {
        qDebug() << "*** Failed to load library";
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool MainWindow::loadLibrary()
{
    lib.setFileName("UntrustedDll.dll");
    if (!lib.load()) {
        qDebug() << "*** library not loaded";
        return false;
    }
    setPersonalData = (t_setPersonalData) lib.resolve("setPersonalData");
    if (!setPersonalData) {
        qDebug() << "*** setPersonalData function not loaded";
        return false;
    }
    accessPersonalData = (t_accessPersonalData) lib.resolve("accessPersonalData");
    if (!accessPersonalData) {
        qDebug() << "*** accessPersonalData function not loaded";
        return false;
    }
    return true;
}

/* функция считывает учётные записи из файла JSON в стурктуру данных QLjst */
bool MainWindow::readJSON(const QByteArray &aes256_key)
{
    QFile jsonFile("credentials_100_en.json");
    jsonFile.open(QFile::ReadOnly);
    if(!jsonFile.isOpen())
        return false;

    QByteArray hexEncryptedBytes = jsonFile.readAll();
    QByteArray encryptedBytes = QByteArray::fromHex(hexEncryptedBytes);
    //qDebug() << encryptedBytes;
    QByteArray decryptedBytes;
    int ret_code = decryptFile(aes256_key, encryptedBytes, decryptedBytes);
    qDebug() << "ret_code = " << ret_code;

    QJsonParseError jsonErr;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedBytes, &jsonErr);
    if (jsonErr.error != QJsonParseError::NoError)
        return false;


    QJsonObject rootObject = jsonDoc.object();

    /*
    QJsonArray sitesArray;
    for (auto itm : rootObject["credit"].toArray()) {
        qDebug() << "*** itm = " << itm;
        QJsonObject siteObject;
        siteObject["site"] = itm.toObject()["site"];
        sitesArray.append(siteObject);
    }

    m_jsonarray = sitesArray;
    for (auto itm : m_jsonarray) {
        qDebug() << "*** m_jsonarray itm = " << itm;
    }
    */
    QJsonArray jsonArray = rootObject["credit"].toArray();

    //запись данных в анклав
    for (int i = 0; i < jsonArray.size(); ++i) {
        QJsonObject jsonObject = jsonArray[i].toObject();
        QString jsonString = QString(QJsonDocument(jsonObject).toJson(QJsonDocument::Compact));
        QByteArray jsonBytes = jsonString.toUtf8();
        qDebug() << "*** setPersonalData jsonBytes.constData()" << const_cast<char*>(jsonBytes.constData());
        setPersonalData(const_cast<char*>(jsonBytes.constData()), jsonBytes.size(), i);
    }
    char buffer[1024] = {0};
    accessPersonalData(buffer, 1024, 1);
    qDebug() << "*** accessPersonalData in readJSON = " << buffer;


    return true;
}

void MainWindow::filterList(const QString &text)
{
    ui->listWidget->clear();
    qDebug() << "*** text" << text;

    for (int i = 0; i < 100; ++i) { // Предполагаем 100 учетных записей (можно изменить)
        char buffer[1024] = {0};
        accessPersonalData(buffer, 1024, i);
        qDebug() << "*** accessPersonalData in filterList = " << buffer;

        QJsonDocument jsonDoc = QJsonDocument::fromJson(QByteArray(buffer));
        QJsonObject jsonObject = jsonDoc.object();
        QString site = jsonObject["site"].toString();

        if (site.contains(text, Qt::CaseInsensitive) || text.isEmpty()) {
            QListWidgetItem *item = new QListWidgetItem();
            credentialwidget *itemWidget = new credentialwidget(site, i);
            QObject::connect(itemWidget, &credentialwidget::decryptLoginPassword,
                             this, &MainWindow::decryptLoginPassword);

            item->setSizeHint(itemWidget->sizeHint());
            ui->listWidget->addItem(item);
            ui->listWidget->setItemWidget(item, itemWidget);
        }
    }

}

int MainWindow::decryptFile(
        const QByteArray &aes256_key,
        const QByteArray &encryptedBytes,
        QByteArray &decryptedBytes){
    // задать ключ и инициализирующий вектор
    //QByteArray key_ba = QByteArray::fromHex(aes256_key);
    unsigned char key[32] = {0};
    memcpy(key, aes256_key.data(), 32);

    QByteArray iv_ba = QByteArray::fromHex("29f11f244ea40f11facffd580a776e30");
    unsigned char iv[16] = {0};
    memcpy(iv, iv_ba.data(), 16);

    //const int BUF_LEN = 256;

    //hex(key) = a6c284830c59bdea0d6f227758eee57e8e23a93dd8ffcd243b40ca39f00d78d1
    //hex(iv) = 29f11f244ea40f11facffd580a776e30

    EVP_CIPHER_CTX *ctx; //заводится контекст
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL)) {
        qDebug() << "EVP_DecryptInit_ex2 ERROR";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    qDebug() << "EVP_DecryptInit_ex2() 0K";
    int outLen = encryptedBytes.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc());
        decryptedBytes.resize(outLen);

    int decryptedLen = 0;
    if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(decryptedBytes.data()), &outLen,
                           reinterpret_cast<const unsigned char*>(encryptedBytes.constData()), encryptedBytes.size())) {
        qDebug() << "EVP_DecryptUpdate ERROR";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    decryptedLen = outLen;

    if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(decryptedBytes.data()) + decryptedLen, &outLen)) {
        qDebug() << "EVP_DecryptFinal_ex ERROR";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    decryptedLen += outLen;

    EVP_CIPHER_CTX_free(ctx);
    decryptedBytes.resize(decryptedLen);
    return 1;

}

void MainWindow::on_editPin_returnPressed()
{
    QByteArray hash = QCryptographicHash::hash(ui->editPin->text().toUtf8(), QCryptographicHash::Sha256);
    qDebug() << "Hash" << hash.toHex();

    if (m_isStartup) {
        if (readJSON(hash)) {
            ui->stackedWidget->setCurrentIndex(1);
            filterList("");
            m_isStartup = false;
            char buffer[1024] = {0};
            accessPersonalData(buffer, 1024, 1);
            qDebug() << "*** accessPersonalData in m_isStartup = " << buffer;

        } else {
            ui->labLogin->setText("Неверный пин");
            ui->labLogin->setStyleSheet("color:red;");
        }

    } else {

        char buffer[1024] = {0};
        accessPersonalData(buffer, 1024, m_current_id);
        qDebug() << "*** accessPersonalData in clipboard = " << buffer;

        QJsonDocument jsonDoc = QJsonDocument::fromJson(QByteArray(buffer));
        QJsonObject jsonObject = jsonDoc.object();

        if (m_field) {
            QGuiApplication::clipboard()->setText(jsonObject["login"].toString());
        } else {
            QGuiApplication::clipboard()->setText(jsonObject["password"].toString());
        }


        //QGuiApplication::clipboard()->setText(QString::fromUtf8(decrypted_creds));
        ui->stackedWidget->setCurrentIndex(1);
    }

    ui->editPin->setText(QString().fill('*',  ui->editPin->text().size()));
    ui->editPin->clear();
    hash.setRawData(const_cast<const char*>(QByteArray().fill('*', 32).data()), 32);
    hash.clear();

}

void MainWindow::decryptLoginPassword(int id, credentialwidget::FIELD field)
{
    qDebug() << "*** slot decryptLoginPassword()";
    //qDebug() << m_jsonarray[id].toObject()["logpass"].toString();
    qDebug() << "*** field" << field;
    m_field = field;
    m_current_id = id;
    qDebug() << "*** m_current_id" << m_current_id;
    ui->stackedWidget->setCurrentIndex(0);
}
