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
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButton_enc_clicked();
    void on_pushButton_dec_clicked();


    void on_textEdit_in_cursorPositionChanged();
    void on_textEdit_in_selectionChanged();

    void on_textEdit_out_cursorPositionChanged();
    void on_textEdit_out_selectionChanged();


    void on_lineEdit_key_cursorPositionChanged(int arg1, int arg2);

    void on_lineEdit_key_selectionChanged();

    void on_lineEdit_iv_cursorPositionChanged(int arg1, int arg2);

    void on_lineEdit_iv_selectionChanged();

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



    void on_textEdit_char_in_cursorPositionChanged();

    void on_textEdit_char_in_selectionChanged();

    void on_textEdit_char_in_2_cursorPositionChanged();

    void on_textEdit_char_in_2_selectionChanged();

    void on_textEdit_char_out_cursorPositionChanged();

    void on_textEdit_char_out_selectionChanged();

    void on_tabWidget_tabBarClicked(int index);

    void on_pushButton_rsa_gen_clicked();

private:
    Ui::MainWindow *ui;
    QLabel *WaringLabel;  //显示警告信息
    QLabel *PosLabel; //显示pos:  光标位置
    QLabel *SelLabel; //显示Sel:  选取字符数
};

#endif // MAINWINDOW_H
