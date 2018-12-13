#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class QLabel;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void edit_selectionChanged();
    void line_cursorPositionChanged(int arg1, int arg2);
    void text_cursorPositionChanged();

    void on_pushButton_enc_clicked();

    void on_pushButton_dec_clicked();

    void on_pushButton_asctohex_clicked();

    void on_pushButton_hextoasc_clicked();

    void on_pushButton_upper_clicked();

    void on_pushButton_lower_clicked();

    void on_pushButton_xor_clicked();

    void on_pushButton_not_clicked();

    void on_pushButton_trim_clicked();

    void on_pushButton_base64tohex_clicked();

    void on_pushButton_hextobase64_clicked();



    void on_pushButton_save_clicked();

    void on_pushButton_load_clicked();



    void on_pushButton_rsa_gen_clicked();

    void on_pushButton_rsa_pkenc_clicked();

    void on_pushButton_rsa_vkdec_clicked();

    void on_pushButton_rsa_vkenc_clicked();

    void on_pushButton_rsa_pkdec_clicked();



    void on_pushButton_hash_clicked();


    void on_btn_SM2_GenPair_clicked();

    void on_btn_SM2_Encrypt_clicked();

    void on_btn_SM2_Decrypt_clicked();

    void on_btn_SM2_sign_clicked();

    void on_btn_SM2_verify_clicked();

private:
    Ui::MainWindow *ui;
    QLabel *m_labelPos;
    QLabel *m_labelSel;
    QLabel *m_labelMsg;
};

#endif // MAINWINDOW_H
