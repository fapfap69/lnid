/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Client che chiede l'hostname ad un server LNID

 Copyright (c) 2024 Antonio Franco

 Questo programma è rilasciato sotto la licenza Creative Commons Attribuzione 4.0 Internazionale (CC BY 4.0).
 Puoi condividere, copiare, distribuire e modificare il programma, a condizione di dare il dovuto credito all'autore originale.

 Licenza completa: https://creativecommons.org/licenses/by/4.0/
 
 auth. A.Franco - INFN Bary Italy
 date: 28/11/2024       ver.1.1

 ---------------------------------------------------------
  HISTORY 
  28/11/2024  -  Creation

 ---------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

#include "lnid-lib.h"
#include "lnid-ssl.h"

// Variabili Globali
extern int isVerbose;

int theListeningPort = DEFAULT_PORT;
char *theServerIp = NULL;
char theMesBuf[BUFFER_SIZE] = "HOSTNAME";
char *theMessage = theMesBuf;

int isRSA = 0; // Is the comunication RSA
OSSL_LIB_CTX *osslLibCtx = NULL;

// Funzione per stampare l'uso del programma
void print_usage() {
    fprintf(stdout,"***  Local Network Identity Discovery Client  ***\n");
    fprintf(stdout," Auth: A.Franco - INFN Bari Italy \n");
    fprintf(stdout," Date : 06/12/2024 -  Ver. 2.0    \n\n");
    fprintf(stdout,"Utilizzo: lnid-cli -i <indirizzo_ip> -p <porta> -d -v -h\n");
    fprintf(stdout,"  -i <indirizzo_ip> : specifica l'indirizzo IP del server\n");
    fprintf(stdout,"  -p <porta>        : specifica la porta da utilizzare (default=16969)\n");
    fprintf(stdout,"  -d                : ritorna il PID\n");
    fprintf(stdout,"  -m                : ritorna il MAC addr\n");
    fprintf(stdout,"  -c                : attiva la modalità cifrata\n");
    fprintf(stdout,"  -v                : attiva la modalità verbose\n");
    fprintf(stdout,"  -h                : visualizza l'help\n");
    return;
}

// Decodifica la command line e setta le variabili
void decode_cmdline(int argc, char *argv[]) {
 
    // Controlla se ci sono abbastanza argomenti
    if (argc < 1) {
        print_usage();
        exit(EXIT_FAILURE); // Error exit code
    }

    // Elaborazione degli argomenti
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            // Validazione IP address
            struct sockaddr_in sa;
            if (inet_pton(AF_INET, argv[i+1], &(sa.sin_addr)) != 1) {
                fprintf(stderr, "Errore: indirizzo IP non valido: %s\n", argv[i+1]);
                exit(EXIT_FAILURE);
            }
            theServerIp = argv[i+1];
            i++; // Salta l'argomento dell'IP
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            int port = atoi(argv[i + 1]);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Errore: porta deve essere tra 1 e 65535\n");
                exit(EXIT_FAILURE);
            }
            theListeningPort = port;
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-v") == 0) {
            isVerbose = 1;
        }
        else if (strcmp(argv[i], "-c") == 0) {
            isRSA = 1;
        }
        else if (strcmp(argv[i], "-d") == 0) {
            strncpy(theMessage, "ID", sizeof(theMesBuf) - 1);
            theMessage[sizeof(theMesBuf) - 1] = '\0';
        }
        else if (strcmp(argv[i], "-m") == 0) {
            strncpy(theMessage, "MAC", sizeof(theMesBuf) - 1);
            theMessage[sizeof(theMesBuf) - 1] = '\0';
        }
        else if (strcmp(argv[i], "-h") == 0) {
            print_usage();
            exit(EXIT_SUCCESS); // Error exit code
        }
        else {
            fprintf(stdout,"Opzione non valida: %s\n", argv[i]);
            print_usage();
            exit(EXIT_FAILURE); // Error exit code
        }
    }

    // Verifica se sono stati forniti i parametri necessari
    if (theServerIp == NULL || theListeningPort == 0) {
        fprintf(stdout,"Errore: IP o porta errata.\n");
        exit(EXIT_FAILURE); // Error exit code
    }

    // Stampa delle informazioni di configurazione
    if(isVerbose) {
        fprintf(stdout,"Configurazione:\n");
        fprintf(stdout,"  Server: %s\n", theServerIp);
        fprintf(stdout,"  Porta: %d\n", theListeningPort);
        fprintf(stdout,"  Richiesta: %s\n", theMessage);
        fprintf(stdout,"  Modalità cifrata %s\n", isRSA == 0 ? "disattivata" : "attivata" );
        fprintf(stdout,"  Modalità verbose attivata\n");
    }
    return;
} 

int main(int argc, char *argv[]) 
{
    char response[RESPONSE_SIZE]; 
    EVP_PKEY *pairKey = NULL;

    // legge la command line 
    decode_cmdline(argc, argv);
    
    // Set up per la cifratura
    if(isRSA) {
        char *passphrase = NULL;
        // Inizializza file temporanei sicuri
        initSecureTempFiles();
        
        pairKey = generateRsaKeyPair(KEY_SIZE); // genera la coppia di chiavi
        if(pairKey == NULL) { 
            cleanupSecureTempFiles();
            exit(EXIT_FAILURE); 
        } 
        storeKeyInPEM(pairKey, PUBKEYFILEC, EVP_PKEY_PUBLIC_KEY, passphrase);
        storeKeyInPEM(pairKey, PRIVKEYFILEC, EVP_PKEY_KEYPAIR, passphrase);
    }

    int ret = sendUdpRequest(theServerIp, response, pairKey, theListeningPort, theMessage, isRSA);
    fprintf(stdout,"Risposta dal server (%d) %s = >%s<\n", ret, theServerIp, response);
    
    // Cleanup
    if(isRSA) {
        cleanupSecureTempFiles();
    }
    exit(EXIT_SUCCESS);
}


