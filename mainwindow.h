/**
 * @author Maissa Rémi
 * @abstract Ce fichier est le header de mainWindow.h
 * @date 18/11/2021
 * @version 2.0 beta
 */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QMap>
#include <QVector>



namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void debloquerIp();
    QTimer *monTimer;
    void programmeBan();
    int compteurExecution = 0;
    void affichageConsole(QString commande);
    int nombreBoucle = 0;

private:
    Ui::MainWindow *ui;
    QMap<QString,QVector<long>> maIp;


public slots :

    void boucleProgramme();

private slots:
    void on_pushButtonRetirer_clicked();
    void on_pushButtonAjouter_clicked();
};

#endif // MAINWINDOW_H
