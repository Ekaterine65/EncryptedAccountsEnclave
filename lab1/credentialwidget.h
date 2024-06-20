#ifndef CREDENTIALWIDGET_H
#define CREDENTIALWIDGET_H

#include <QWidget>

namespace Ui {
class credentialwidget;
}

class credentialwidget : public QWidget
{
    Q_OBJECT

public:
    explicit credentialwidget(const QString &site,
                              const int id,
                              QWidget *parent = nullptr);
    ~credentialwidget();

    enum FIELD {
        LOGIN, PASSWORD
    };

private slots:
    void on_copyLog_clicked();

    void on_copyPass_clicked();

signals:
    void decryptLoginPassword(int id, FIELD field);
    //void decryptLogin(int id);

private:
    Ui::credentialwidget *ui;
    int m_id = -1;
};

#endif // CREDENTIALWIDGET_H
