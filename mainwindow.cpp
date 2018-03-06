#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "openssl_api.h"
#include "myhelper.h"

#include <QTextCursor>




MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //默认勾选 DES  ECB
    ui->radioButton_ecb->setChecked(true);
    ui->radioButton_des->setChecked(true);

    ui->radioButton_pkcs1->setChecked(true);

    ui->radioButton_md5->setChecked(true);

    WaringLabel = new QLabel;
    PosLabel = new QLabel;
    SelLabel = new QLabel;

    WaringLabel->setStyleSheet("color:red;font: bold 20px");

    PosLabel->setStyleSheet("font: 18px");
    SelLabel->setStyleSheet("font: 18px");
    PosLabel->setText("Pos:0");
    SelLabel->setText("Sel:0");

    ui->statusBar->addWidget(WaringLabel);       //警告信息 显示在左侧
    ui->statusBar->addPermanentWidget(PosLabel);
    ui->statusBar->addPermanentWidget(SelLabel);
}

MainWindow::~MainWindow()
{
    delete ui;
    delete WaringLabel;
    delete PosLabel;
    delete SelLabel;
}

void MainWindow::on_tabWidget_tabBarClicked(int index)
{
    WaringLabel->setText( "" );
    SelLabel->setText( QString("Sel:%1").arg(0) );
    PosLabel->setText( QString("Pos:%1").arg(0) );
}


//加密
void MainWindow::on_pushButton_enc_clicked()
{
    QString keyHex = ui->lineEdit_key->text();
    if (keyHex.isEmpty()) {
        WaringLabel->setText( tr("key is empty") );
        return;
    }

    QString ivHex = "";
    if( !ui->radioButton_ecb->isChecked() )
    {
        ivHex = ui->lineEdit_iv->text();
        if (ivHex.isEmpty()) {            
            WaringLabel->setText( tr("iv is empty") );
            return;
        }
    }


    QString inHex = ui->textEdit_in->toPlainText();
    if (inHex.isEmpty()) {        
        WaringLabel->setText( tr("input is empty") );
        return;
    }

    //选择加密算法和加密模式
    int alg,mode;
    if( ui->radioButton_des->isChecked() ){
        alg = DES;
    }else if( ui->radioButton_aes->isChecked()){
        alg = AES;
    }else if( ui->radioButton_sm4->isChecked()){
        alg = SM4;
    }
    if( ui->radioButton_ecb->isChecked() ){
        mode = ECB;
    }else if( ui->radioButton_cbc->isChecked()){
        mode = CBC;
    }else if( ui->radioButton_cfb->isChecked()){
        mode = CFB;
    }else if( ui->radioButton_ofb->isChecked()){
        mode = OFB;
    }


    ui->textEdit_out->clear();

    QString outHex;
    int ret = 0;
    ret = OPENSSL_API::enc(keyHex,ivHex,alg,mode,inHex,outHex);
    if(ret<0){
        WaringLabel->setText( tr("enc error") );
        return;
    }

    WaringLabel->setText( tr("") );

    ui->textEdit_out->setText(outHex);
    return;
}

void MainWindow::on_pushButton_dec_clicked()
{
    QString keyHex = ui->lineEdit_key->text();
    if (keyHex.isEmpty()) {
        WaringLabel->setText( tr("key is empty") );
        return;
    }

    QString ivHex = "";
    if( !ui->radioButton_ecb->isChecked() )
    {
        ivHex = ui->lineEdit_iv->text();
        if (ivHex.isEmpty()) {
            WaringLabel->setText( tr("iv  is empty") );
            return;
        }
    }


    QString inHex = ui->textEdit_in->toPlainText();
    if (inHex.isEmpty()) {
        WaringLabel->setText( tr("input is empty") );
        return;
    }

    //选择解密算法和解密模式
    int alg,mode;
    if( ui->radioButton_des->isChecked() ){
        alg = DES;
    }else if( ui->radioButton_aes->isChecked()){
        alg = AES;
    }else if( ui->radioButton_sm4->isChecked()){
        alg = SM4;
    }
    if( ui->radioButton_ecb->isChecked() ){
        mode = ECB;
    }else if( ui->radioButton_cbc->isChecked()){
        mode = CBC;
    }else if( ui->radioButton_cfb->isChecked()){
        mode = CFB;
    }else if( ui->radioButton_ofb->isChecked()){
        mode = OFB;
    }


    ui->textEdit_out->clear();

    QString outHex;
    int ret = 0;
    ret = OPENSSL_API::dec(keyHex,ivHex,alg,mode,inHex,outHex);
    if(ret<0){
        WaringLabel->setText( tr("dec error") );
        return;
    }

    WaringLabel->setText( tr("") );

    ui->textEdit_out->setText(outHex);
    return;

}



void MainWindow::on_textEdit_in_cursorPositionChanged()
{
    int pos = ui->textEdit_in->textCursor().position();
    PosLabel->setText(QString("Pos:%1").arg(pos));
}


void MainWindow::on_textEdit_in_selectionChanged()
{
    QTextCursor cur = ui->textEdit_in->textCursor();
    int len = cur.selectionEnd() - cur.selectionStart();
    SelLabel->setText( QString("Sel:%1").arg(len) );
}


void MainWindow::on_textEdit_out_cursorPositionChanged()
{
    int pos = ui->textEdit_out->textCursor().position();
    PosLabel->setText(QString("Pos:%1").arg(pos));
}

void MainWindow::on_textEdit_out_selectionChanged()
{
    QTextCursor cur = ui->textEdit_out->textCursor();
    int len = cur.selectionEnd() - cur.selectionStart();
    SelLabel->setText( QString("Sel:%1").arg(len) );
}
///////////////////对称算法对话框  end//////////////////////


void MainWindow::on_lineEdit_key_cursorPositionChanged(int arg1, int arg2)
{
    int pos = ui->lineEdit_key->cursorPosition();
    PosLabel->setText(QString("Pos:%1").arg(pos));
}

void MainWindow::on_lineEdit_key_selectionChanged()
{
    int len = ui->lineEdit_key->selectedText().length();
    SelLabel->setText( QString("Sel:%1").arg(len) );
}

void MainWindow::on_lineEdit_iv_cursorPositionChanged(int arg1, int arg2)
{
    int pos = ui->lineEdit_iv->cursorPosition();
    PosLabel->setText(QString("Pos:%1").arg(pos));
}

void MainWindow::on_lineEdit_iv_selectionChanged()
{
    int len = ui->lineEdit_iv->selectedText().length();
    SelLabel->setText( QString("Sel:%1").arg(len) );
}



///////////////////字符处理  ///////////////////////
void MainWindow::on_pushButton_asctohex_clicked()
{
    WaringLabel->setText("");
    QString in = ui->textEdit_char_in->toPlainText();
    if (in.isEmpty() ){
        return;
    }
    //QString  outHex = myHelper::byteArrayToHexStr(in.toUtf8());
    QString  outHex ( in.toUtf8().toHex() );
    outHex.toUpper();
    ui->textEdit_char_out->setText(outHex);
}

void MainWindow::on_pushButton_hextoasc_clicked()
{
    WaringLabel->setText("");
    QString in = ui->textEdit_char_in->toPlainText();
    if (in.isEmpty() ){
        return;
    }
    QByteArray tbyte = QByteArray::fromHex( in.toUtf8() );
    if( tbyte.isEmpty()){
        WaringLabel->setText("data error");
        return ;
    }
    QString outAsc(tbyte);
    ui->textEdit_char_out->setText(outAsc);
}

void MainWindow::on_pushButton_upper_clicked()
{
    WaringLabel->setText("");
    QString in = ui->textEdit_char_in->toPlainText();
    ui->textEdit_char_out->setText(in.toUpper());
}

void MainWindow::on_pushButton_lower_clicked()
{
    WaringLabel->setText("");
    QString in = ui->textEdit_char_in->toPlainText();
    ui->textEdit_char_out->setText(in.toLower());
}

void MainWindow::on_pushButton_xor_clicked()
{
    WaringLabel->setText("");
    QString in1 = ui->textEdit_char_in->toPlainText();
    QString in2 = ui->textEdit_char_in_2->toPlainText();

    QByteArray bytein1 =  QByteArray::fromHex(in1.toUtf8());
    QByteArray bytein2 =  QByteArray::fromHex(in2.toUtf8());

    if( bytein1.isEmpty()){
        WaringLabel->setText("in1 error");
        return ;
    }
    if( bytein2.isEmpty()){
        WaringLabel->setText("in2 error");
        return ;
    }
    if( bytein1.length() != bytein2.length()){
        WaringLabel->setText("data len not equal");
        return ;
    }

    QByteArray result;
    for(int i=0;i<bytein1.length();i++){
        result.append( bytein1.at(i) ^ bytein2.at(i) );
    }
    QString strResult =  result.toHex();
    ui->textEdit_char_out->setText(strResult.toUpper());
}

void MainWindow::on_pushButton_not_clicked()
{
    WaringLabel->setText("");

    QString in1 = ui->textEdit_char_in->toPlainText();
    QByteArray bytein1 =  QByteArray::fromHex(in1.toUtf8());
    if( bytein1.isEmpty()){
        WaringLabel->setText("in1 error");
        return ;
    }
    QByteArray bytein2(bytein1.length() , (char)0xff);

    QByteArray result;
    for(int i=0;i<bytein1.length();i++){
        result.append( bytein1.at(i) ^ bytein2.at(i) );
    }
    QString strResult =  result.toHex();
    ui->textEdit_char_out->setText(strResult.toUpper());
}

void MainWindow::on_pushButton_trim_clicked()
{
    WaringLabel->setText("");
    QString in = ui->textEdit_char_in->toPlainText();

    QString trimStr = ui->lineEdit_trim_str->text();

    QString out ;
    if( trimStr.isEmpty()){

        for(int i =0;i<in.length();i++){
            if(in.at(i).isSpace()){
                in.remove(i,1);
            }
        }
    }
    else{
        in.remove( trimStr,  Qt::CaseSensitive);
    }
    ui->textEdit_char_out->setText(in);
}

void MainWindow::on_pushButton_base64tohex_clicked()
{
    WaringLabel->setText("");
    QString in = ui->textEdit_char_in->toPlainText();
    QByteArray bytet = QByteArray::fromBase64( in.toUtf8() );
    QString strt(bytet.toHex());
    ui->textEdit_char_out->setText(strt.toUpper());
}

void MainWindow::on_pushButton_hextobase64_clicked()
{
    WaringLabel->setText("");
    QString in = ui->textEdit_char_in->toPlainText();
    QByteArray bytet = QByteArray::fromHex( in.toUtf8() );
    QString strt( bytet.toBase64() );
    ui->textEdit_char_out->setText(strt);
}



void MainWindow::on_pushButton_save_clicked()
{
    WaringLabel->setText("");
    QString in = ui->textEdit_char_in->toPlainText();
    QByteArray bytet = QByteArray::fromHex( in.toUtf8() );

    QString path = QFileDialog::getSaveFileName(this,tr("Save File"),  ".",   tr("bin(*.bin);;*(*)"));
    if(!path.isEmpty()) {
        QFile file(path);
        if ( !file.open(QIODevice::ReadWrite) )
        {
            QMessageBox::warning(this, tr("Save File"),  tr("Cannot save file:\n%1").arg(path));
            return;
        }
        if( bytet.length() != file.write(bytet) ){
            QMessageBox::warning(this, tr("Save File"),  tr("Cannot save file:\n%1").arg(path));
        }
        file.close();
    }
    else{
        QMessageBox::warning(this, tr("Save File"),  tr("Cannot save file:\n%1").arg(path));
    }
}

void MainWindow::on_pushButton_load_clicked()
{
    QByteArray bytet;
    QString path = QFileDialog::getOpenFileName(this,tr("Open File"),  ".",   tr("bin(*.bin);;*(*)"));
    if(!path.isEmpty()) {
        QFile file(path);
        if ( !file.open(QIODevice::ReadOnly) )
        {
            QMessageBox::warning(this, tr("Open File"),  tr("Cannot Open file:\n%1").arg(path));
            return;
        }
        bytet = file.readAll();

        file.close();
    }
    else{
        QMessageBox::warning(this, tr("Open File"),  tr("Cannot save file:\n%1").arg(path));
    }

    QByteArray byteHex =  bytet.toHex();
    QString outStr(byteHex);
    ui->textEdit_char_out->setText(outStr.toUpper());
}



void MainWindow::on_textEdit_char_in_cursorPositionChanged()
{
    int pos = ui->textEdit_char_in->textCursor().position();
    PosLabel->setText(QString("Pos:%1").arg(pos));
}

void MainWindow::on_textEdit_char_in_selectionChanged()
{
    QTextCursor cur = ui->textEdit_char_in->textCursor();
    int len = cur.selectionEnd() - cur.selectionStart();
    SelLabel->setText( QString("Sel:%1").arg(len) );
}

void MainWindow::on_textEdit_char_in_2_cursorPositionChanged()
{
    int pos = ui->textEdit_char_in_2->textCursor().position();
    PosLabel->setText(QString("Pos:%1").arg(pos));
}

void MainWindow::on_textEdit_char_in_2_selectionChanged()
{
    QTextCursor cur = ui->textEdit_char_in_2->textCursor();
    int len = cur.selectionEnd() - cur.selectionStart();
    SelLabel->setText( QString("Sel:%1").arg(len) );
}

void MainWindow::on_textEdit_char_out_cursorPositionChanged()
{
    int pos = ui->textEdit_char_out->textCursor().position();
    PosLabel->setText(QString("Pos:%1").arg(pos));
}

void MainWindow::on_textEdit_char_out_selectionChanged()
{
    QTextCursor cur = ui->textEdit_char_out->textCursor();
    int len = cur.selectionEnd() - cur.selectionStart();
    SelLabel->setText( QString("Sel:%1").arg(len) );
}
///////////////////字符处理  end///////////////////////


///////////////////rsa  ///////////////////////
void MainWindow::on_pushButton_rsa_gen_clicked()
{
    QString bits = ui->lineEdit_bits->text();
    QString e = ui->lineEdit_e->text();

    QString derpk;
    QString dervk;
    OPENSSL_API::genrsa(bits,e,derpk,dervk);

    ui->textEdit_pk->setText(derpk.toUpper());
    ui->textEdit_vk->setText(dervk.toUpper());

}



void MainWindow::on_pushButton_rsa_pkenc_clicked()
{
    QString derpk;
    QString in;
    QString out;
    int padding;
    int ret = 0;

    const int  RSA_PKCS1_PADDING      = 1;
    const int  RSA_SSLV23_PADDING     = 2;
    const int  RSA_NO_PADDING         = 3;
    const int  RSA_PKCS1_OAEP_PADDING = 4;
    const int  RSA_X931_PADDING       = 5;

    derpk = ui->textEdit_pk->toPlainText();
    in    = ui->textEdit_rsa_in->toPlainText();

    if( ui->radioButton_nopading->isChecked() )
         padding = RSA_NO_PADDING;
    else if( ui->radioButton_pkcs1->isChecked() )
         padding = RSA_PKCS1_PADDING;

    ret = OPENSSL_API::rsa_pkenc(derpk,in,padding,out);
    if( ret <0 ){
        WaringLabel->setText("encrypt error");
    }
    ui->textEdit_rsa_out->setText(out.toUpper());

}

void MainWindow::on_pushButton_rsa_vkdec_clicked()
{
    QString dervk;
    QString in;
    QString out;
    int padding;
    int ret = 0;

    const int  RSA_PKCS1_PADDING      = 1;
    const int  RSA_SSLV23_PADDING     = 2;
    const int  RSA_NO_PADDING         = 3;
    const int  RSA_PKCS1_OAEP_PADDING = 4;
    const int  RSA_X931_PADDING       = 5;

    dervk = ui->textEdit_vk->toPlainText();
    in    = ui->textEdit_rsa_in->toPlainText();

    if( ui->radioButton_pkcs1->isChecked() )
         padding = RSA_PKCS1_PADDING;
    else if( ui->radioButton_nopading->isChecked() )
         padding = RSA_NO_PADDING;


    ret = OPENSSL_API::rsa_vkdec(dervk,in,padding,out);
    if( ret <0 ){
        WaringLabel->setText("decrypt error");
    }
    ui->textEdit_rsa_out->setText(out.toUpper());

}

void MainWindow::on_pushButton_rsa_vkenc_clicked()
{
    QString dervk;
    QString in;
    QString out;
    int padding;
    int ret = 0;

    const int  RSA_PKCS1_PADDING      = 1;
    const int  RSA_SSLV23_PADDING     = 2;
    const int  RSA_NO_PADDING         = 3;
    const int  RSA_PKCS1_OAEP_PADDING = 4;
    const int  RSA_X931_PADDING       = 5;

    dervk = ui->textEdit_vk->toPlainText();
    in    = ui->textEdit_rsa_in->toPlainText();

    if( ui->radioButton_pkcs1->isChecked() )
         padding = RSA_PKCS1_PADDING;
    else if( ui->radioButton_nopading->isChecked() )
         padding = RSA_NO_PADDING;


    ret = OPENSSL_API::rsa_vkenc(dervk,in,padding,out);
    if( ret <0 ){
        WaringLabel->setText("encrypt error");
    }
    ui->textEdit_rsa_out->setText(out.toUpper());
}

void MainWindow::on_pushButton_rsa_pkdec_clicked()
{
    QString derpk;
    QString in;
    QString out;
    int padding;
    int ret = 0;

    const int  RSA_PKCS1_PADDING      = 1;
    const int  RSA_SSLV23_PADDING     = 2;
    const int  RSA_NO_PADDING         = 3;
    const int  RSA_PKCS1_OAEP_PADDING = 4;
    const int  RSA_X931_PADDING       = 5;

    derpk = ui->textEdit_pk->toPlainText();
    in    = ui->textEdit_rsa_in->toPlainText();

    if( ui->radioButton_nopading->isChecked() )
         padding = RSA_NO_PADDING;
    else if( ui->radioButton_pkcs1->isChecked() )
         padding = RSA_PKCS1_PADDING;

    ret = OPENSSL_API::rsa_pkdec(derpk,in,padding,out);
    if( ret <0 ){
        WaringLabel->setText("decrypt error");
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
    in = ui->textEdit_hash_in->toPlainText();

    if( ui->radioButton_md5->isChecked() )
        alg = 1;
    else if( ui->radioButton_sm3->isChecked() )
         alg = 2;
    else if( ui->radioButton_iso->isChecked() )
         alg = 3;
    else if( ui->radioButton_sha1->isChecked() )
         alg = 4;
    else if( ui->radioButton_sha224->isChecked() )
         alg = 5;
    else if( ui->radioButton_sha256->isChecked() )
         alg = 6;
    else if( ui->radioButton_sha384->isChecked() )
         alg = 7;
    else if( ui->radioButton_sha512->isChecked() )
         alg = 8;

    ret = OPENSSL_API::hash(in,alg,out);
    if(ret<0){
        WaringLabel->setText("message digest error");
    }
    ui->textEdit_hash_out->setText(out.toUpper());
}
///////////////////////hash end/////////////////



//////////////////////sm2 //////////////////
void MainWindow::on_pushButton_sm2_gen_clicked()
{
    QString d;
    QString x;
    QString y;
    int ret = 0;
    ret = OPENSSL_API::gensm2(x,y,d);
    if( ret<0 ){
        return ;
    }
    ui->lineEdit_x->setText(x);
    ui->lineEdit_y->setText(y);
    ui->lineEdit_d_2->setText(d);
}



void MainWindow::on_pushButton_sm2_enc_clicked()
{
    QString pkx;
    QString pky;
    QString in;
    QString out;
    int ret = 0;

    pkx = ui->lineEdit_x->text();
    pky = ui->lineEdit_y->text();
    in = ui->textEdit_sm2_in->toPlainText();

    ret = OPENSSL_API::sm2enc(pkx,pky ,in , out);
    if(ret<0){
        WaringLabel->setText("sm2 enc error");
        return ;
    }

    ui->textEdit_sm2_out->setText(out.toUpper());
}

void MainWindow::on_pushButton_sm2_dec_clicked()
{

}

void MainWindow::on_pushButton_sm2_sign_clicked()
{
    QString d;
    QString data;
    QString pkx;
    QString pky;
    QString uid;
    QString hash;
    QString sign;
    int ret = -1;

    pkx = ui->lineEdit_x->text();
    pky = ui->lineEdit_y->text();
    uid = ui->lineEdit_uid->text();
    d   = ui->lineEdit_d_2->text();
    data= ui->textEdit_sm2_in->toPlainText();

    if( ui->checkBox_interHash->isChecked() ){
        OPENSSL_API::sm3_hash(pkx,pky,uid,data,hash);
    }
    else{
        if(data.length()!=64){
            WaringLabel->setText("hash value should be 64 hex");
            return ;
        }
        hash = data;
    }

    ret =  OPENSSL_API::sm2sign(d,hash,sign );
    if(ret<=0){
        WaringLabel->setText("sign failed");
        return ;
    }

    ui->textEdit_sm2_out->setText( sign.toUpper() );
    return ;

}

void MainWindow::on_pushButton_sm2_verify_clicked()
{
    QString pkx;
    QString pky;
    QString uid;
    QString data;
    QString sign;
    QString hash;
    int ret = -1;


    pkx = ui->lineEdit_x->text();
    pky = ui->lineEdit_y->text();
    uid = ui->lineEdit_uid->text();
    data = ui->textEdit_sm2_in->toPlainText();
    sign = ui->textEdit_sm2_out->toPlainText();

    if( ui->checkBox_interHash->isChecked() ){
        OPENSSL_API::sm3_hash(pkx,pky,uid,data,hash);
    }
    else{
        if(data.length()!=64){
            WaringLabel->setText("hash value should be 64 hex");
            return ;
        }
        hash = data;
    }

    ret = OPENSSL_API::sm2verify(pkx,pky,hash,sign);
    if(ret<=0){
        WaringLabel->setText("verify failed");
        return ;
    }
    WaringLabel->setText("verify success");
    return ;
}
