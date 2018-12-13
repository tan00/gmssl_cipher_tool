#include <QDebug>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "openssl_api.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QTextCursor>

#pragma execution_character_set("utf-8")

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_labelPos = new QLabel;
    m_labelPos->setText("当前位置: 0");
    //m_labelPos->sizeHint().setWidth(200);
    //m_labelPos->setMinimumSize(m_labelPos->sizeHint());
    m_labelPos->setAlignment(Qt::AlignHCenter);

    m_labelSel = new QLabel;
    m_labelSel->setText("选择长度: 0");
    //m_labelSel->sizeHint().setWidth(200);
    //m_labelSel->setMinimumSize(m_labelSel->sizeHint());
    m_labelSel->setAlignment(Qt::AlignHCenter);

    m_labelMsg = new QLabel;
    //m_labelMsg->setText("");
    //m_labelMsg->sizeHint().setWidth(200);
    //m_labelMsg->setMinimumSize(m_labelMsg->sizeHint());
    m_labelMsg->setAlignment(Qt::AlignHCenter);

    statusBar()->addWidget(m_labelPos);
    statusBar()->addWidget(m_labelSel);
    statusBar()->addWidget(m_labelMsg);
    //statusBar()->setStyleSheet(QString("QStatusBar::item{border: 0px}"));

    // enc
    QObject::connect(ui->line_enc_key, &QLineEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);
    QObject::connect(ui->line_enc_ivec, &QLineEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);
    QObject::connect(ui->text_enc_input, &QTextEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);
    QObject::connect(ui->text_enc_output, &QTextEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);

    QObject::connect(ui->line_enc_key, &QLineEdit::cursorPositionChanged, this, &MainWindow::line_cursorPositionChanged);
    QObject::connect(ui->line_enc_ivec, &QLineEdit::cursorPositionChanged, this, &MainWindow::line_cursorPositionChanged);
    QObject::connect(ui->text_enc_input, &QTextEdit::cursorPositionChanged, this, &MainWindow::text_cursorPositionChanged);
    QObject::connect(ui->text_enc_output, &QTextEdit::cursorPositionChanged, this, &MainWindow::text_cursorPositionChanged);

    // sm2
    QObject::connect(ui->line_sm2_PrivKey, &QLineEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);
    QObject::connect(ui->line_sm2_PubKeyX, &QLineEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);
    QObject::connect(ui->line_sm2_PubKeyY, &QLineEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);
    QObject::connect(ui->line_sm2_uid,     &QLineEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);
    QObject::connect(ui->text_sm2_msg, &QTextEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);
    QObject::connect(ui->text_sm2_hex, &QTextEdit::selectionChanged, this, &MainWindow::edit_selectionChanged);

    QObject::connect(ui->line_sm2_PrivKey, &QLineEdit::cursorPositionChanged, this, &MainWindow::line_cursorPositionChanged);
    QObject::connect(ui->line_sm2_PubKeyX, &QLineEdit::cursorPositionChanged, this, &MainWindow::line_cursorPositionChanged);
    QObject::connect(ui->line_sm2_PubKeyY, &QLineEdit::cursorPositionChanged, this, &MainWindow::line_cursorPositionChanged);
    QObject::connect(ui->line_sm2_uid,     &QLineEdit::cursorPositionChanged, this, &MainWindow::line_cursorPositionChanged);
    QObject::connect(ui->text_sm2_msg, &QTextEdit::cursorPositionChanged, this, &MainWindow::text_cursorPositionChanged);
    QObject::connect(ui->text_sm2_hex, &QTextEdit::cursorPositionChanged, this, &MainWindow::text_cursorPositionChanged);

    //默认勾选 DES  ECB
    ui->radioButton_ecb->setChecked(true);
    ui->radioButton_des->setChecked(true);

    ui->radioButton_pkcs1->setChecked(true);

    ui->radioButton_md5->setChecked(true);
    ui->text_sm2_msg->setPlainText("daisutao is a good programmer!");
}

MainWindow::~MainWindow()
{
    delete ui;
    delete m_labelPos;
    delete m_labelSel;
    delete m_labelMsg;
}

void MainWindow::edit_selectionChanged()
{
    QObject *object = QObject::sender();
    QLineEdit *lineEdit = qobject_cast<QLineEdit *>(object);
    QTextEdit *textEdit = qobject_cast<QTextEdit *>(object);

    if (lineEdit) {
        int len = lineEdit->selectedText().length();
        m_labelSel->setText(QString("选择长度: %1").arg(len));
    } else {
        QTextCursor cur = textEdit->textCursor();
        m_labelSel->setText(QString("选择长度: %1").arg(cur.selectionEnd() - cur.selectionStart()));
    }
}

void MainWindow::line_cursorPositionChanged(int arg1, int arg2)
{
    m_labelPos->setText(QString("当前位置: %1").arg(arg2));
}

void MainWindow::text_cursorPositionChanged()
{
    QObject *object = QObject::sender();

    int pos = qobject_cast<QTextEdit *>(object)->textCursor().position();
    m_labelPos->setText(QString("当前位置: %1").arg(pos));
}

//加密
void MainWindow::on_pushButton_enc_clicked()
{
    QString keyHex = ui->line_enc_key->text();
    if (keyHex.isEmpty()) {
        QMessageBox::information(this, "消息", tr("key is empty"));
        return;
    }

    QString ivHex = "";
    if (!ui->radioButton_ecb->isChecked()) {
        ivHex = ui->line_enc_ivec->text();
        if (ivHex.isEmpty()) {
            QMessageBox::information(this, "消息", tr("iv is empty"));
            return;
        }
    }

    QString inHex = ui->text_enc_input->toPlainText();
    if (inHex.isEmpty()) {
        QMessageBox::information(this, "消息", tr("input is empty"));
        return;
    }

    //选择加密算法和加密模式
    int alg = 0, mode = 0;
    if (ui->radioButton_des->isChecked())
        alg = DES;
    else if (ui->radioButton_aes->isChecked())
        alg = AES;
    else if (ui->radioButton_sm4->isChecked())
        alg = SM4;
    if (ui->radioButton_ecb->isChecked())
        mode = ECB;
    else if (ui->radioButton_cbc->isChecked())
        mode = CBC;
    else if (ui->radioButton_cfb->isChecked())
        mode = CFB;
    else if (ui->radioButton_ofb->isChecked())
        mode = OFB;


    ui->text_enc_output->clear();

    QString outHex;
    int ret = 0;
    ret = OPENSSL_API::enc(keyHex, ivHex, alg, mode, inHex, outHex);
    if (ret < 0) {
        QMessageBox::information(this, "消息", tr("enc error"));
        return;
    }

    ui->text_enc_output->setText(outHex);
    return;
}

void MainWindow::on_pushButton_dec_clicked()
{
    QString keyHex = ui->line_enc_key->text();
    if (keyHex.isEmpty()) {
        QMessageBox::information(this, "消息", tr("key is empty"));
        return;
    }

    QString ivHex = "";
    if (!ui->radioButton_ecb->isChecked()) {
        ivHex = ui->line_enc_ivec->text();
        if (ivHex.isEmpty()) {
            QMessageBox::information(this, "消息", tr("iv  is empty"));
            return;
        }
    }

    QString inHex = ui->text_enc_input->toPlainText();
    if (inHex.isEmpty()) {
        QMessageBox::information(this, "消息", tr("input is empty"));
        return;
    }

    //选择解密算法和解密模式
    int alg = 0, mode = 0;
    if (ui->radioButton_des->isChecked())
        alg = DES;
    else if (ui->radioButton_aes->isChecked())
        alg = AES;
    else if (ui->radioButton_sm4->isChecked())
        alg = SM4;
    if (ui->radioButton_ecb->isChecked())
        mode = ECB;
    else if (ui->radioButton_cbc->isChecked())
        mode = CBC;
    else if (ui->radioButton_cfb->isChecked())
        mode = CFB;
    else if (ui->radioButton_ofb->isChecked())
        mode = OFB;

    ui->text_enc_output->clear();

    QString outHex;
    int ret = 0;
    ret = OPENSSL_API::dec(keyHex, ivHex, alg, mode, inHex, outHex);
    if (ret < 0) {
        QMessageBox::information(this, "消息", tr("dec error"));
        return;
    }
    ui->text_enc_output->setText(outHex);
    return;
}
///////////////////对称算法对话框  end//////////////////////

///////////////////字符处理  ///////////////////////
void MainWindow::on_pushButton_asctohex_clicked()
{
    QString in = ui->textEdit_char_in->toPlainText();
    if (in.isEmpty())
        return;
    QString  outHex(in.toUtf8().toHex());
    ui->textEdit_char_out->setText(outHex.toUpper());
}

void MainWindow::on_pushButton_hextoasc_clicked()
{
    QString in = ui->textEdit_char_in->toPlainText();
    if (in.isEmpty())
        return;
    QByteArray tbyte = QByteArray::fromHex(in.toUtf8());
    if (tbyte.isEmpty()) {
        QMessageBox::information(this, "消息", tr("data error"));
        return ;
    }
    QString outAsc(tbyte);
    ui->textEdit_char_out->setText(outAsc);
}

void MainWindow::on_pushButton_upper_clicked()
{
    QString in = ui->textEdit_char_in->toPlainText();
    ui->textEdit_char_out->setText(in.toUpper());
}

void MainWindow::on_pushButton_lower_clicked()
{
    QString in = ui->textEdit_char_in->toPlainText();
    ui->textEdit_char_out->setText(in.toLower());
}

void MainWindow::on_pushButton_xor_clicked()
{
    QString in1 = ui->textEdit_char_in->toPlainText();
    QString in2 = ui->textEdit_char_in_2->toPlainText();

    QByteArray bytein1 =  QByteArray::fromHex(in1.toUtf8());
    QByteArray bytein2 =  QByteArray::fromHex(in2.toUtf8());

    if (bytein1.isEmpty()) {
        QMessageBox::information(this, "消息", tr("in1 error"));
        return ;
    }
    if (bytein2.isEmpty()) {
        QMessageBox::information(this, "消息", tr("in2 error"));
        return ;
    }
    if (bytein1.length() != bytein2.length()) {
        QMessageBox::information(this, "消息", tr("data len not equal"));
        return ;
    }

    QByteArray result;
    for (int i = 0; i < bytein1.length(); i++)
        result.append(bytein1.at(i) ^ bytein2.at(i));
    QString strResult =  result.toHex();
    ui->textEdit_char_out->setText(strResult.toUpper());
}

void MainWindow::on_pushButton_not_clicked()
{
    QString in1 = ui->textEdit_char_in->toPlainText();
    QByteArray bytein1 =  QByteArray::fromHex(in1.toUtf8());
    if (bytein1.isEmpty()) {
        QMessageBox::information(this, "消息", tr("in1 error"));
        return ;
    }
    QByteArray bytein2(bytein1.length(), '\xff');

    QByteArray result;
    for (int i = 0; i < bytein1.length(); i++)
        result.append(bytein1.at(i) ^ bytein2.at(i));
    QString strResult =  result.toHex();
    ui->textEdit_char_out->setText(strResult.toUpper());
}

void MainWindow::on_pushButton_trim_clicked()
{
    QString in = ui->textEdit_char_in->toPlainText();
    QString trimStr = ui->lineEdit_trim_str->text();
    QString out ;
    if (trimStr.isEmpty()) {

        for (int i = 0; i < in.length(); i++) {
            if (in.at(i).isSpace() || in.at(i).toLatin1() == '\n')
                in.remove(i, 1);
        }
    } else
        in.remove(trimStr,  Qt::CaseSensitive);
    ui->textEdit_char_out->setText(in);
}

void MainWindow::on_pushButton_base64tohex_clicked()
{
    QString in = ui->textEdit_char_in->toPlainText();
    QByteArray bytet = QByteArray::fromBase64(in.toUtf8());
    QString strt(bytet.toHex());
    ui->textEdit_char_out->setText(strt.toUpper());
}

void MainWindow::on_pushButton_hextobase64_clicked()
{
    QString in = ui->textEdit_char_in->toPlainText();
    QByteArray bytet = QByteArray::fromHex(in.toUtf8());
    QString strt(bytet.toBase64());
    ui->textEdit_char_out->setText(strt);
}



void MainWindow::on_pushButton_save_clicked()
{
    QString in = ui->textEdit_char_in->toPlainText();
    QByteArray bytet = QByteArray::fromHex(in.toUtf8());

    QString path = QFileDialog::getSaveFileName(this, tr("Save File"),  ".",   tr("bin(*.bin);;*(*)"));
    if (!path.isEmpty()) {
        QFile file(path);
        if (!file.open(QIODevice::ReadWrite)) {
            QMessageBox::warning(this, tr("Save File"),  tr("Cannot save file:\n%1").arg(path));
            return;
        }
        if (bytet.length() != file.write(bytet))
            QMessageBox::warning(this, tr("Save File"),  tr("Cannot save file:\n%1").arg(path));
        file.close();
    } else
        QMessageBox::warning(this, tr("Save File"),  tr("Cannot save file:\n%1").arg(path));
}

void MainWindow::on_pushButton_load_clicked()
{
    QByteArray bytet;
    QString path = QFileDialog::getOpenFileName(this, tr("Open File"),  ".",   tr("bin(*.bin);;*(*)"));
    if (!path.isEmpty()) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, tr("Open File"),  tr("Cannot Open file:\n%1").arg(path));
            return;
        }
        bytet = file.readAll();

        file.close();
    } else
        QMessageBox::warning(this, tr("Open File"),  tr("Cannot save file:\n%1").arg(path));

    QByteArray byteHex =  bytet.toHex();
    QString outStr(byteHex);
    ui->textEdit_char_out->setText(outStr.toUpper());
}
///////////////////字符处理  end///////////////////////


///////////////////rsa  ///////////////////////
void MainWindow::on_pushButton_rsa_gen_clicked()
{
    QString bits = ui->lineEdit_bits->text();
    QString e = ui->lineEdit_e->text();

    QString derpk;
    QString dervk;
    OPENSSL_API::genrsa(bits, e, derpk, dervk);

    ui->textEdit_pk->setText(derpk.toUpper());
    ui->textEdit_vk->setText(dervk.toUpper());
}



void MainWindow::on_pushButton_rsa_pkenc_clicked()
{
    QString derpk;
    QString in;
    QString out;
    int padding = 0;
    int ret = 0;

    const int  RSA_PKCS1_PADDING      = 1;
    const int  RSA_SSLV23_PADDING     = 2;
    const int  RSA_NO_PADDING         = 3;
    const int  RSA_PKCS1_OAEP_PADDING = 4;
    const int  RSA_X931_PADDING       = 5;

    derpk = ui->textEdit_pk->toPlainText();
    in    = ui->textEdit_rsa_in->toPlainText();

    if (ui->radioButton_nopading->isChecked())
        padding = RSA_NO_PADDING;
    else if (ui->radioButton_pkcs1->isChecked())
        padding = RSA_PKCS1_PADDING;

    ret = OPENSSL_API::rsa_pkenc(derpk, in, padding, out);
    if (ret < 0)
        QMessageBox::information(this, "消息", tr("encrypt error"));
    ui->textEdit_rsa_out->setText(out.toUpper());

}

void MainWindow::on_pushButton_rsa_vkdec_clicked()
{
    QString dervk;
    QString in;
    QString out;
    int padding = 0;
    int ret = 0;

    const int  RSA_PKCS1_PADDING      = 1;
    const int  RSA_SSLV23_PADDING     = 2;
    const int  RSA_NO_PADDING         = 3;
    const int  RSA_PKCS1_OAEP_PADDING = 4;
    const int  RSA_X931_PADDING       = 5;

    dervk = ui->textEdit_vk->toPlainText();
    in    = ui->textEdit_rsa_in->toPlainText();

    if (ui->radioButton_pkcs1->isChecked())
        padding = RSA_PKCS1_PADDING;
    else if (ui->radioButton_nopading->isChecked())
        padding = RSA_NO_PADDING;

    ret = OPENSSL_API::rsa_vkdec(dervk, in, padding, out);
    if (ret < 0) {
        QMessageBox::information(this, "消息", tr("decrypt error"));
        return;
    }
    ui->textEdit_rsa_out->setText(out.toUpper());
}

void MainWindow::on_pushButton_rsa_vkenc_clicked()
{
    QString dervk;
    QString in;
    QString out;
    int padding = 0;
    int ret = 0;

    const int  RSA_PKCS1_PADDING      = 1;
    const int  RSA_SSLV23_PADDING     = 2;
    const int  RSA_NO_PADDING         = 3;
    const int  RSA_PKCS1_OAEP_PADDING = 4;
    const int  RSA_X931_PADDING       = 5;

    dervk = ui->textEdit_vk->toPlainText();
    in    = ui->textEdit_rsa_in->toPlainText();

    if (ui->radioButton_pkcs1->isChecked())
        padding = RSA_PKCS1_PADDING;
    else if (ui->radioButton_nopading->isChecked())
        padding = RSA_NO_PADDING;


    ret = OPENSSL_API::rsa_vkenc(dervk, in, padding, out);
    if (ret < 0) {
        QMessageBox::information(this, "消息", tr("encrypt error"));
        return;
    }
    ui->textEdit_rsa_out->setText(out.toUpper());
}

void MainWindow::on_pushButton_rsa_pkdec_clicked()
{
    QString derpk;
    QString in;
    QString out;
    int padding = 0;
    int ret = 0;

    const int  RSA_PKCS1_PADDING      = 1;
    const int  RSA_SSLV23_PADDING     = 2;
    const int  RSA_NO_PADDING         = 3;
    const int  RSA_PKCS1_OAEP_PADDING = 4;
    const int  RSA_X931_PADDING       = 5;

    derpk = ui->textEdit_pk->toPlainText();
    in    = ui->textEdit_rsa_in->toPlainText();

    if (ui->radioButton_nopading->isChecked())
        padding = RSA_NO_PADDING;
    else if (ui->radioButton_pkcs1->isChecked())
        padding = RSA_PKCS1_PADDING;

    ret = OPENSSL_API::rsa_pkdec(derpk, in, padding, out);
    if (ret < 0) {
        QMessageBox::information(this, "消息", tr("decrypt error"));
        return;
    }
    ui->textEdit_rsa_out->setText(out.toUpper());
}
///////////////////rsa  end///////////////////////


///////////////////////hash /////////////////
void MainWindow::on_pushButton_hash_clicked()
{
    QString in;
    int alg = 0;
    QString out;
    int ret = 0;
    in = ui->text_hash_input->toPlainText();

    if (ui->radioButton_md5->isChecked())
        alg = 1;
    else if (ui->radioButton_sm3->isChecked())
        alg = 2;
    else if (ui->radioButton_iso->isChecked())
        alg = 3;
    else if (ui->radioButton_sha1->isChecked())
        alg = 4;
    else if (ui->radioButton_sha224->isChecked())
        alg = 5;
    else if (ui->radioButton_sha256->isChecked())
        alg = 6;
    else if (ui->radioButton_sha384->isChecked())
        alg = 7;
    else if (ui->radioButton_sha512->isChecked())
        alg = 8;

    ret = OPENSSL_API::hash(in, alg, out);
    if (ret < 0) {
        QMessageBox::information(this, "消息", tr("message digest error"));
        return;
    }
    ui->text_hash_output->setText(out.toUpper());
}
///////////////////////hash end/////////////////


//////////////////////  SM2  //////////////////
void MainWindow::on_btn_SM2_GenPair_clicked()
{
    QString d, p_x, p_y;
    int ret = 0;
    ret = OPENSSL_API::sm2gen(p_x, p_y, d);
    if (ret < 0) {
        m_labelMsg->setText("sm2 gen error");
        return;
    }
    ui->line_sm2_PrivKey->setText(d);
    ui->line_sm2_PubKeyX->setText(p_x);
    ui->line_sm2_PubKeyY->setText(p_y);
    m_labelMsg->setText("生成密钥完成！");
}

void MainWindow::on_btn_SM2_Encrypt_clicked()
{
    QString p_x, p_y;
    QString msg, hex;
    int ret = 0;

    p_x = ui->line_sm2_PubKeyX->text();
    p_y = ui->line_sm2_PubKeyY->text();
    msg = ui->text_sm2_msg->toPlainText();
    ret = OPENSSL_API::sm2enc(p_x, p_y, msg, hex);
    if (ret < 0) {
        m_labelMsg->setText("sm2 enc error");
        return ;
    }

    ui->text_sm2_hex->setText(hex.toUpper());
    m_labelMsg->setText("加密完成！");
}

void MainWindow::on_btn_SM2_Decrypt_clicked()
{
    QString d, p_x, p_y;
    QString hex, msg;
    int ret = 0;

    d = ui->line_sm2_PrivKey->text();
    hex = ui->text_sm2_hex->toPlainText();
    ret = OPENSSL_API::sm2dec(d, hex, msg);
    if (ret < 0) {
        m_labelMsg->setText("sm2 dec error");
        return ;
    }

    ui->text_sm2_msg->setText(msg);
    m_labelMsg->setText("解密成功！");
}

void MainWindow::on_btn_SM2_sign_clicked()
{
    QString d, p_x, p_y, uid, msg, hex;

    int ret = -1;

    d   = ui->line_sm2_PrivKey->text();
    p_x = ui->line_sm2_PubKeyX->text();
    p_y = ui->line_sm2_PubKeyY->text();
    uid = ui->line_sm2_uid->text();
    msg = ui->text_sm2_msg->toPlainText();

    ret = OPENSSL_API::sm2sign(d, p_x, p_y, uid, msg, hex);
    if (ret <= 0) {
        m_labelMsg->setText("sign failed");
        return;
    }
    ui->text_sm2_hex->setText(hex.toUpper());
    m_labelMsg->setText("签名完成！");
}

void MainWindow::on_btn_SM2_verify_clicked()
{
    QString p_x, p_y, uid, msg, hex;

    int ret = -1;

    p_x = ui->line_sm2_PubKeyX->text();
    p_y = ui->line_sm2_PubKeyY->text();
    uid = ui->line_sm2_uid->text();
    msg = ui->text_sm2_msg->toPlainText();
    hex = ui->text_sm2_hex->toPlainText();

    ret = OPENSSL_API::sm2verify(p_x, p_y, uid, msg, hex);
    if (ret <= 0) {
        m_labelMsg->setText("verify failed");
        return;
    }
    m_labelMsg->setText("验签成功！");
}
