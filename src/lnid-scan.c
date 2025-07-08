/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Scanner che ritorna tutti i server LNID su di una sottorete

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
int theDelay = 150; // milliseconds
char theSubNet[50] = "192.168.0.0";
char theNetMask[50] = "255.255.255.0";
char theResponse[RESPONSE_SIZE];
time_t theTimeOutSec = TIMEOUT_SEC;
useconds_t theTimeOutUSec = TIMEOUT_USEC;

int isRSA = 0; // Is the comunication RSA
OSSL_LIB_CTX *osslLibCtx = NULL;

// Funzione per stampare l'uso del programma
void print_usage() {
    fprintf(stdout,"***  Local Network Identity Discovery Scanner  ***\n");
    fprintf(stdout," Auth: A.Franco - INFN Bari Italy \n");
    fprintf(stdout," Date : 06/12/2024 -  Ver. 2.0    \n\n");
    fprintf(stdout,"Utilizzo: lnid-scan -s <indirizzo_subnet> -p <porta> -t <milliseconds> -o <milliseconds> -d -v -h\n");
    fprintf(stdout,"  -s <indirizzo_subnet> : specifica la subnet\n");
    fprintf(stdout,"  -p <porta>        : specifica la porta da utilizzare (default=16969)\n");
    fprintf(stdout,"  -t <milliseconds> : ritardo fra scansioni successive (default=50\n");
    fprintf(stdout,"  -o <milliseconds> : timeout in ricezione (default=100\n");
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
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            strncpy(theSubNet, argv[i + 1], sizeof(theSubNet) - 1);
            theSubNet[sizeof(theSubNet) - 1] = '\0';
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
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            int delay = atoi(argv[i + 1]);
            if (delay < 0 || delay > 10000) {
                fprintf(stderr, "Errore: delay deve essere tra 0 e 10000 ms\n");
                exit(EXIT_FAILURE);
            }
            theDelay = delay;
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            long mills = atoi(argv[i + 1]);
            if (mills <= 0) mills = 100; // Default 100ms
            theTimeOutSec = (time_t)(mills / 1000);
            theTimeOutUSec = (useconds_t)((mills % 1000) * 1000);
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
    if (*theSubNet == '\0' || theListeningPort == 0) {
        fprintf(stdout,"Errore: SubNet o porta errata.\n");
        exit(EXIT_FAILURE); // Error exit code
    }
    if(theTimeOutSec == 0 && theTimeOutUSec == 0) {
        theTimeOutSec = 0;
        theTimeOutUSec = 100000; // 100ms default
    }

    // Costruisce il valore della SubNet e della Maschera
    int nu;
    char *ptr = theSubNet;
    for (nu = 0; *ptr != '\0'; ptr++) if (*ptr == '.') nu++;
    switch (nu) {
        case 0:
            strcpy(theNetMask, "255.0.0.0");
            strncat(theSubNet, ".0.0.0", 49);
            break;
        case 1:
            strcpy(theNetMask, "255.255.0.0");
            strncat(theSubNet, ".0.0", 49);
            break;
        case 2:
            strcpy(theNetMask, "255.255.255.0");
            strncat(theSubNet, ".0", 49);
            break;
        default:
            fprintf(stdout,"Errore: SubNet %s non ammessa.\n", theSubNet);
            exit(EXIT_FAILURE); // Error exit code
            break;
    }

    // Stampa delle informazioni di configurazione
    if(isVerbose) {
        fprintf(stdout,"Configurazione:\n");
        fprintf(stdout,"  Subnet: %s\n", theSubNet);
        fprintf(stdout,"  Mask: %s\n", theNetMask);
        fprintf(stdout,"  Porta: %d\n", theListeningPort);
        fprintf(stdout,"  Ritardo: %d\n", theDelay);
        fprintf(stdout,"  Timeout: %ld\n", (long)theTimeOutSec * 1000 + ((long)theTimeOutUSec/1000));
        fprintf(stdout,"  Richiesta: %s\n", theMessage);
        fprintf(stdout,"  Modalità cifrata %s\n", isRSA == 0 ? "disattivata" : "attivata" );
        fprintf(stdout,"  Modalità verbose attivata\n");
    }
    return;
} 

// Funzione per generare gli indirizzi IP in una sottorete
void scan_subnet(const char *subnet, const char *mask, EVP_PKEY *pairKey)
{
    static int requests_sent = 0;
    const int MAX_SCAN_REQUESTS = 1000; // Limite richieste per scan
    time_t scan_start = time(NULL);
    
    // Crea gli indirzzi
    struct in_addr subnet_addr, mask_addr;
    inet_pton(AF_INET, subnet, &subnet_addr);
    inet_pton(AF_INET, mask, &mask_addr);

    // Maschera inversa per ottenere la gamma degli IP
    unsigned int start_ip = ntohl(subnet_addr.s_addr) & ntohl(mask_addr.s_addr);
    unsigned int end_ip = start_ip | ~ntohl(mask_addr.s_addr);
    
    // Controllo dimensione scan
    unsigned int total_ips = end_ip - start_ip - 1;
    if (total_ips > MAX_SCAN_REQUESTS) {
        fprintf(stderr, "Scansione troppo ampia (%u IPs), limitata a %d\n", total_ips, MAX_SCAN_REQUESTS);
        end_ip = start_ip + MAX_SCAN_REQUESTS + 1;
    }
    
    if(isVerbose) fprintf(stdout,"Scansione della sottorete %s con maschera %s...\n", subnet, mask);
    if(isVerbose) fprintf(stdout,"Timeout : %lds.  %luus, Delay: %dms\n", theTimeOutSec, theTimeOutUSec, theDelay);
    // Scansione della gamma di indirizzi IP
    for (unsigned int ip = start_ip + 1; ip < end_ip; ip++) {
        // Conversione da int a stringa IP
        struct in_addr ip_addr;
        ip_addr.s_addr = htonl(ip);
        char ip_string[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_addr, ip_string, INET_ADDRSTRLEN);

        // Controllo limite richieste
        requests_sent++;
        if (requests_sent > MAX_SCAN_REQUESTS) {
            if(isVerbose) fprintf(stdout,"Limite richieste raggiunto\n");
            break;
        }
        
        // Controllo timeout totale scan (max 10 minuti)
        if (time(NULL) - scan_start > 600) {
            if(isVerbose) fprintf(stdout,"Timeout scansione raggiunto\n");
            break;
        }
        
        // Invia la richiesta UDP a questo IP
        if(sendUdpRequestWithTimeout(ip_string, theResponse, pairKey, theListeningPort,theMessage,isRSA, theTimeOutSec, theTimeOutUSec) == TRUE) { // ok
            fprintf(stdout,"%s %s\n",ip_string, theResponse);
        }

        // Inserisce un delay minimo per evitare flooding
        int min_delay = (theDelay < 10) ? 10 : theDelay;
        usleep(min_delay * 1000);
    }
    return;
}

int main(int argc, char *argv[])
{
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

    // Esegui lo scan della sottorete
    scan_subnet(theSubNet, theNetMask, pairKey);
    
    // Cleanup
    if(isRSA) {
        cleanupSecureTempFiles();
    }
    exit(EXIT_SUCCESS);
}

