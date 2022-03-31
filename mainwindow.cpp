#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QTimer>
#include <QFile>
#include <QTextStream>
#include <QProcess>
#include <QtDebug>
#include <QStringList>
#include <QDateTime>
#include <QLocale>
#include <QString>
#include <QThread>
#include <QScrollBar>

#define NBRMAXTENTATIVE 3

/**
 * @brief Cette fonction est le constructeur de l'application, il initialise la fenetre et permet de lancer le timer pour la boucle
 * @param parent
 */
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //on met les titres des colones du tableWidget en stretch
    ui->tableWidgetTableau->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    //initialisation du timer
    monTimer = new QTimer();
    QObject::connect(monTimer, SIGNAL(timeout()), this,SLOT(boucleProgramme()));

    //on lance la boucle
    boucleProgramme();

}

MainWindow::~MainWindow()
{
    delete ui;
}
/**
 * @brief Cette fonction permet de verifier si les tentatives des ip bloqués sont datée de moins de 5 minutes ou non, et les débannies si la derniere connexion
 * date de plus de 5 minutes.
 */
void MainWindow::debloquerIp()
{
    qDebug()<<"debloquerIp";
    //boucle sur la Qmap
    QMapIterator<QString,QVector<long>> iterateur(maIp);
    while(iterateur.hasNext())
    {
        iterateur.next();
        QString ip = iterateur.key();
        QVector<long> vectInfo = iterateur.value();
        long nbTentatives = vectInfo[0];
        if(nbTentatives>=3 && QDateTime::currentMSecsSinceEpoch()-vectInfo[1] >= 1000*60*5)
        {
            qDebug()<<"on deban l'ip";
            //5 minutes écoulées, on les debloques
            QString cmdObtentionNoLigneBlocage = "/sbin/iptables -L --line-numbers | grep "+ip+"> /tmp/ligneASuppr";
            system(cmdObtentionNoLigneBlocage.toStdString().c_str());

            QFile monFic("/tmp/ligneASuppr");
            monFic.open(QIODevice::ReadOnly | QIODevice::Text);
            QTextStream monTS(&monFic);
            QString ligneLu = monTS.readLine();
            //j'obtient le numero de la ligne a supprimer
            QString numeroLigne = ligneLu.split(" ").at(0);
            qDebug()<<"numeroLigne : "<<numeroLigne;
            //je construit ma commande systeme
            QString cmdDeblocage = "/sbin/iptables -D INPUT "+numeroLigne;
            //je l'execute
            system(cmdDeblocage.toStdString().c_str());
            //je supprime l'ip de la map
            maIp.remove(ip);

            //on previens dans la console
            affichageConsole("Utilisateur débanni ! Adresse : "+ip);

            //on supprime la ligne de l'ip dans le tableTableau
            for(int compteur = ui->tableWidgetTableau->rowCount()-1 ; compteur >= 0; compteur--)
            {
                QString ipLigne = ui->tableWidgetTableau->item(compteur,0)->text();
                //on prend la ligne et on verifie si l'ip est la
                if(ipLigne == ip)
                {
                    //on supprime la ligne
                    ui->tableWidgetTableau->removeRow(compteur);
                }; //fin if
            }


        }
    }
    qDebug()<<"fin debloquerIp";
}

/**
 * @brief Cette fonction permet de verifie les fichiers de log a la recherche de connexions recentes, puis enregistre les Ip et la derniere date de connexion.
 * Si les connexions sont plus nombreuse que le nombre de tentative autorisé, alors les Ip sont bloqué et stockées.
 */
void MainWindow::programmeBan()
{
    //mon code
    QString commandeLigneLog = "wc -l /var/log/auth.log | cut -d' ' -f1 > /tmp/nbrLigneActuel.txt";
    system(commandeLigneLog.toStdString().c_str());

    //ouverture du fichier du nombre de ligne
    QFile fichierActuel("/tmp/nbrLigneActuel.txt");
    fichierActuel.open(QIODevice::ReadOnly | QIODevice::Text);

    QString strLigneFichier;

    while (!(fichierActuel.atEnd()))
    {
        strLigneFichier = fichierActuel.readLine();
    }

    //on obtient le nombre de ligne de /var/log/auth.log
    int nbrLigneFichier = strLigneFichier.toInt();

    //on recupere le nombre de ligne precedant
    QFile fichierPrecedant("/tmp/nbrLignePrecedant.txt");
    fichierPrecedant.open(QIODevice::ReadOnly | QIODevice::Text);

    QString strNbrLignePrecedant;

    while (!(fichierPrecedant.atEnd()))
    {
        strNbrLignePrecedant = fichierPrecedant.readLine();
    }
    int precedentNbrLigneFichier = strNbrLignePrecedant.toInt();

    //on calcule le nombre de difference entre nbrLigne actuel et precedent
    int differenceNbrLigne = nbrLigneFichier - precedentNbrLigneFichier;

    //si differenceNbrLigne != 0
    if(differenceNbrLigne != 0 )
    {
        qDebug()<<"entrer if differenceLigne";
        //on creer la commande pour afficher le nombre de ligne de difference
        //on recherche toutes les adresses IP des messages de refus de connection
        QString commandeTail = "tail -"+QString::number(differenceNbrLigne)+" /var/log/auth.log | grep 'Failed password' | awk '{split($0,a,"+'"'+"from "+'"'+"); print a[2]}' | cut -d' ' -f1 >  /tmp/log2.txt";
        system(commandeTail.toStdString().c_str());

        QString commandeLog = "tail -"+QString::number(differenceNbrLigne)+" /var/log/auth.log | grep 'Failed password' > /tmp/log.txt";
        system(commandeLog.toStdString().c_str());


        //on ouvre log.txt
        QFile fichierLog("/tmp/log.txt");
        fichierLog.open(QIODevice::ReadOnly);

        //on ouvre log2.txt
        QFile fichierIp("/tmp/log2.txt");
        fichierIp.open(QIODevice::ReadOnly);
        if(fichierLog.isReadable())
        {
            qDebug()<<"lecture possible fichierLog";
        }
        if(fichierIp.isReadable())
        {
            qDebug()<<"lecture possible fichierIp";
        }
        while (!fichierLog.atEnd())
        {
            QString ligneLu = fichierLog.readLine();
            QString adresseIP = fichierIp.readLine();

            //on remplace le \n du saut de ligne du document par un espace
            adresseIP.replace("\n","");

            QStringList listElements = ligneLu.split(" ",QString::SkipEmptyParts);
            QString laDate = QString::number(QDate::currentDate().year())+" "+listElements[0]+" "+listElements[1];
            QString lHeure = listElements[2];

            qDebug()<<"heure"<<lHeure;
            qDebug()<<"date"<<laDate;
            qDebug()<<"adresse ip"<<adresseIP;

            QLocale english = QLocale(QLocale::English);
            //on defini la date
            QDate dateConnexion = english.toDate(laDate,"yyyy MMM d");
            //on cree un QDateTime
            QDateTime dateHeureConnexion ;
            //on ajoute la date au QDateTime
            dateHeureConnexion.setDate(dateConnexion);
            //on defini l'heure
            QTime heureConnexion = QTime::fromString(lHeure,"hh:mm:ss");
            //on l'ajoute dans le QDateTime
            dateHeureConnexion.setTime(heureConnexion);

            qDebug()<<" date et heure trouvé "<<dateHeureConnexion.toString("yyyy MMM d hh:mm:ss");

            QString infoGlobale = dateHeureConnexion.toString("yyyy MMM d hh:mm:ss")+" "+adresseIP+" Failed Connexion";
            //on affiche
            affichageConsole(infoGlobale);

            //si la connexion a moins de 5 min
            if(QDateTime::currentDateTime().toMSecsSinceEpoch()-dateHeureConnexion.toMSecsSinceEpoch()<5*60*1000)
            {
                qDebug()<<"entree if date";

                //on met a jour la map
                if(maIp.contains(adresseIP))
                {

                    qDebug()<<"entree if maIp.contains(adresseIP)";

                    //je met a jour le nombre de tentative
                    QVector<long> vectInfo = maIp.value(adresseIP);

                    //increment du nb de tentative
                    vectInfo[0]++;

                    //je met a jour le time de la derniere connexion
                    vectInfo[1] = dateHeureConnexion.toMSecsSinceEpoch();
                    maIp[adresseIP] = vectInfo;

                    qDebug()<<"QMap = "<<maIp;


                    //on parcourt toute les lignes sur la 1ere case
                    for(int compteur = ui->tableWidgetTableau->rowCount()-1 ; compteur >= 0; compteur--)
                    {
                        QString ipLigne = ui->tableWidgetTableau->item(compteur,0)->text();
                        //on prend la ligne et on verifie si l'ip est la
                        if(ipLigne == adresseIP)
                        {
                            //on met a jour le nombre de tentative
                            ui->tableWidgetTableau->item(compteur,1)->setText(QString::number(vectInfo[0]));
                            //et la date de derniere tentative
                            ui->tableWidgetTableau->item(compteur,2)->setText(dateHeureConnexion.toString("yyyy MMM d hh:mm:ss"));
                        }; //fin if

                    }; //fin for


                    //si le nombre de tentative max est atteint je doit banir l'ip
                    if(vectInfo[0] >= NBRMAXTENTATIVE)
                    {
                        qDebug()<<"entree if  vectInfo[0]>NBRMAXTENTATIVE";

                        //on verifie si l'adresse est deja banni ( arrive a 3 connexion) pour eviter de rajouter une ligne dans la table des bans
                        if(!(maIp[adresseIP][0] > NBRMAXTENTATIVE) )
                        {
                            QString cmdBannissement = "/sbin/iptables -A INPUT -s "+adresseIP+" -j DROP";


                            //iptables -L INPUT --line-numbers | grep DROP
                            //commande pour afficher les ip bloquées avec la ligne

                            qDebug()<<" iptable = "<<cmdBannissement;

                            //j'affiche la commande
                            affichageConsole("Utilisateur banni ! Adresse : "+adresseIP);

                            //je bloque
                            system(cmdBannissement.toStdString().c_str());

                        }
                    }//fin if

                }//fin if

                else
                {
                    qDebug()<<"else if";
                    QVector<long> vectInfo;
                    vectInfo.push_back(1);
                    vectInfo.push_back(dateHeureConnexion.toMSecsSinceEpoch());

                    maIp[adresseIP] = vectInfo;
                    qDebug()<<"QMap = "<<maIp;


                    //on compte le nombre de ligne dans le tableau
                    int nbrLigneLivre = ui->tableWidgetTableau->rowCount();

                    //on insert une ligne
                    ui->tableWidgetTableau->insertRow(nbrLigneLivre);

                    ui->tableWidgetTableau->setItem(nbrLigneLivre,0, new QTableWidgetItem(adresseIP));
                    ui->tableWidgetTableau->setItem(nbrLigneLivre,1, new QTableWidgetItem(QString::number(vectInfo[0])));
                    ui->tableWidgetTableau->setItem(nbrLigneLivre,2, new QTableWidgetItem(dateHeureConnexion.toString("d MMM yyyy hh:mm:ss")));

                    //on informe qu'une nouvelle ip est la
                    QString affFirst = "Nouvelle connexion : "+adresseIP;
                    affichageConsole(affFirst);
                }

            }//fin if

        } //fin while


        //on enregistre le nombre de ligne de /var/log/auth.log pour le comparer ensuite
        //on execute la commande
        qDebug()<<"ecriture nbrLignePrecedant.txt";

        QString nbrLigneFichierString = "echo " +QString::number(nbrLigneFichier)+" > /tmp/nbrLignePrecedant.txt";
        system(nbrLigneFichierString.toStdString().c_str());
    }//fin if

    else
    {
        qDebug()<<"Pas de connexion recente";
    }
    qDebug()<<"fin blocageIp";
}

/**
 * @brief Cette fonction permet de rajouter une ligne dans la console de l'administrateur afin de le prevenir lors d'évenements important.
 * @param commande : QString comportant la ligne à faire afficher dans la console
 */
void MainWindow::affichageConsole(QString commande)
{
    //on ajoute une ligne dans la Console
    ui->textEditConsole->append(commande);

    QScrollBar *scrollbar = ui->textEditConsole->verticalScrollBar();
    bool scrollbarAtBottom  = (scrollbar->value() >= (scrollbar->maximum() - 4));
    int scrollbarPrevValue = scrollbar->value();


    ui->textEditConsole->moveCursor(QTextCursor::End);
    // begin with newline if text is not empty
    if (! ui->textEditConsole->document()->isEmpty())
    {
        ui->textEditConsole->insertHtml(QStringLiteral("<br>"));
    }

    if (scrollbarAtBottom)
    {
        ui->textEditConsole->ensureCursorVisible();
    }
    else
    {
        ui->textEditConsole->verticalScrollBar()->setValue(scrollbarPrevValue);
    }


    QThread::sleep(1);
}

/**
 * @brief Cette fonction permet de faire répéter la boucle
 */
void MainWindow::boucleProgramme()
{
    qDebug()<<"boucleProgramme";
    QDate laDate = QDateTime::currentDateTime().date();


    QString affBoucle = "Nouvelle Execution : "+laDate.toString("d MMM yyyy") +" "+ QTime::currentTime().toString("hh:mm:ss");;

    affichageConsole(affBoucle);
    qDebug()<<"affichageConsole";

    programmeBan();

    debloquerIp();
    monTimer->setSingleShot(true); //active le mode singleShot
    monTimer->start(60000); //démarre une tempo de 15 secondes
}

/**
 * @brief Cette fonction permet de retirer une adresse Ip selectionnée de la liste des Ip bloquées.
 */
void MainWindow::on_pushButtonRetirer_clicked()
{
    qDebug()<<"on_pushButtonRetirer_clicked";
    if(!ui->tableWidgetTableau->selectedItems().isEmpty())
    {
        int numLigneSelect = ui->tableWidgetTableau->currentRow();

        QString ip = ui->tableWidgetTableau->item(numLigneSelect,0)->text();
        QString cmdNumLigne = "/sbin/iptables -L --line-numbers | grep "+ip+"> /tmp/ligneASuppr > /tmp/ligneVoulu.txt";
        system(cmdNumLigne.toStdString().c_str());


        QFile monFic("/tmp/ligneVoulu.txt");
        monFic.open(QIODevice::ReadOnly | QIODevice::Text);
        QTextStream monTS(&monFic);
        QString ligneLu = monTS.readLine();
        QString numeroLigne = ligneLu.split(" ").at(0);
        qDebug()<<"numeroLigne : "<<numeroLigne.replace('"',"");
        //je construit ma commande systeme
        QString cmdDeblocage = "/sbin/iptables -D INPUT "+numeroLigne;

        ui->tableWidgetTableau->removeRow(numLigneSelect);
    }
}

/**
 * @brief Cette fonction permet d'ajouter une Ip ayant déja essayé de se connecté à la liste des Ip bloquées.
 */
void MainWindow::on_pushButtonAjouter_clicked()
{
    qDebug()<<"on_pushButtonAjouter_clicked";

    if(!ui->tableWidgetTableau->selectedItems().isEmpty())
    {
        int numLigneSelect = ui->tableWidgetTableau->currentRow();
        if(!(ui->tableWidgetTableau->item(numLigneSelect,1)->text().toInt() >= 3))
        {
            QString cmdBannissement = "/sbin/iptables -A INPUT -s "+ui->tableWidgetTableau->item(numLigneSelect,0)->text()+" -j DROP";
            system(cmdBannissement.toStdString().c_str());

            ui->tableWidgetTableau->item(numLigneSelect,1)->setText("3");
        }

    }
}
