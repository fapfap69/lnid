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

#define DEFAULT_PORT 16969
#define BUFFER_SIZE 1024
#define TIMEOUT_SEC 2  // Timeout in secondi
#define TIMEOUT_USEC 0 // Timeout in microsecondi

// Variabili Globali
int theListeningPort = DEFAULT_PORT;
int isVerbose = 0;
char *theServerIp = NULL;
char theMessage[25] = "HOSTNAME";

// Funzione per stampare l'uso del programma
void print_usage() {
    printf("***  Local Network Identity Discovery Client  ***\n");
    printf(" Auth: A.Franco - INFN Bari Italy \n");
    printf(" Date : 28/11/2024 -  Ver. 0.1    \n\n");
    printf("Utilizzo: lnid-cli -i <indirizzo_ip> -p <porta> -d -v -h\n");
    printf("  -i <indirizzo_ip> : specifica l'indirizzo IP del server\n");
    printf("  -p <porta>        : specifica la porta da utilizzare (default=16969)\n");
    printf("  -d                : ritorna il PID\n");
    printf("  -m                : ritorna il MAC addr\n");
    printf("  -v               : attiva la modalità verbose\n");
    printf("  -h                : visualizza l'help\n");
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
            theServerIp = argv[i + 1];
            i++; // Salta l'argomento dell'IP
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            theListeningPort = atoi(argv[i + 1]);
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-v") == 0) {
            isVerbose = 1;
        }
        else if (strcmp(argv[i], "-d") == 0) {
            strcpy(theMessage,"ID");
        }
        else if (strcmp(argv[i], "-m") == 0) {
            strcpy(theMessage,"MAC");
        }
        else if (strcmp(argv[i], "-h") == 0) {
            print_usage();
            exit(EXIT_SUCCESS); // Error exit code
        }
        else {
            printf("Opzione non valida: %s\n", argv[i]);
            print_usage();
            exit(EXIT_FAILURE); // Error exit code
        }
    }

    // Verifica se sono stati forniti i parametri necessari
    if (theServerIp == NULL || theListeningPort == 0) {
        printf("Errore: IP o porta errata.\n");
        exit(EXIT_FAILURE); // Error exit code
    }

    // Stampa delle informazioni di configurazione
    if(isVerbose) {
        printf("Configurazione:\n");
        printf("  Server: %s\n", theServerIp);
        printf("  Porta: %d\n", theListeningPort);
        printf("  Richiesta: %s\n", theMessage);
        printf("  Modalità verbose attivata\n");
    }
    return;
} 

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct timeval timeout;
    char buffer[BUFFER_SIZE];

    // legge la command line 
    decode_cmdline(argc, argv);

    // Creazione del socket UDP
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if(isVerbose) printf("Socket creato ...\n");

    // Imposta il timeout per il socket
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = TIMEOUT_USEC;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Errore nell'impostazione del timeout");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Inizializzazione dell'indirizzo del server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(theListeningPort);
    server_addr.sin_addr.s_addr = inet_addr(theServerIp);

    // Invio della richiesta
    sendto(sockfd, theMessage, strlen(theMessage), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if(isVerbose) printf("Richesta del '%s' inviata a:%s:%d \n", theMessage, theServerIp, theListeningPort);

    // Ricezione della risposta
    ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (recv_len < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            if(isVerbose) printf("Timeout raggiunto per %s\n", theServerIp);
        } else {
            perror("Errore durante la ricezione");
        }
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    buffer[recv_len] = '\0';
    printf("Risposta dal server %s: %s\n", theServerIp, buffer);
    close(sockfd);
    exit(EXIT_SUCCESS);
}

