/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Server che ritorna l'hostname ad una richiesta UDP

 Copyright (c) 2024 Antonio Franco

 Questo programma è rilasciato sotto la licenza Creative Commons Attribuzione 4.0 Internazionale (CC BY 4.0).
 Puoi condividere, copiare, distribuire e modificare il programma, a condizione di dare il dovuto credito all'autore originale.

 Licenza completa: https://creativecommons.org/licenses/by/4.0/
 
 auth. A.Franco - INFN Bary Italy
 date: 28/11/2024       ver.1.0

 ---------------------------------------------------------
  HISTORY 
  28/11/2024  -  Creation

 ---------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>

#define DEFAULT_PORT 16969 // Porta su cui ascoltare
#define BUFFER_SIZE 1024

// Variabili Globali
int theListeningPort = DEFAULT_PORT;
int isVerbose = 0;

// Funzione per stampare l'uso del programma
void print_usage() {
    printf("***  Local Network Identity Discovery Server  ***\n");
    printf(" Auth: A.Franco - INFN Bari Italy \n");
    printf(" Date : 28/11/2024 -  Ver. 1.0    \n\n");
    printf("Utilizzo: lnidd -p <porta> -v -h\n");
    printf("  -p <porta>        : specifica la porta da utilizzare  (default=16969)\n");
    printf("  -v                : attiva la modalità verbose\n");
    printf("  -h                : visualizza l'help\n");
    return;
}

// Decodifica la command line e setta le variabili
void decode_cmdline(int argc, char *argv[]) {
 
    // Elaborazione degli argomenti
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            theListeningPort = atoi(argv[i + 1]);
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-v") == 0) {
            isVerbose = 1;
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
    if (theListeningPort == 0) {
        printf("Errore: porta errata.\n");
        exit(EXIT_FAILURE); // Error exit code
    }

    // Stampa delle informazioni di configurazione
    if(isVerbose) {
        printf("Configurazione:\n");
        printf("  Porta: %d\n", theListeningPort);
        printf("  Modalità verbose attivata\n");
    }
    return;
} 

// Funzione per ottenere l'hostname
char* get_hostname() {
    static char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return hostname;
    } else {
        perror("gethostname");
        return "Unknown";
    }
}

// Funzione per ottenere un ID univoco (può essere il PID o qualsiasi altra cosa)
char* get_unique_id() {
    static char id[256];
    snprintf(id, sizeof(id), "ID-%d", getpid()); // Utilizza il PID come ID
    return id;
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // legge la command line 
    decode_cmdline(argc, argv);

    // Creazione del socket UDP
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if(isVerbose) printf("Socket creato \n");

    // Inizializzazione della struttura dell'indirizzo del server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Accetta connessioni su tutte le interfacce
    server_addr.sin_port = htons(theListeningPort);

    // Binding del socket all'indirizzo e alla porta
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    if(isVerbose) printf("Server UDP in ascolto sulla porta %d...\n", theListeningPort);

    while (1) {
        // Ricezione del messaggio
        ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &addr_len);
        if (recv_len < 0) {
            perror("recvfrom");
            continue;
        }

        // Null-terminate il buffer
        buffer[recv_len] = '\0';
        if(isVerbose) printf("Ricevuto messaggio da %s:%d: %s\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);

        // Preparazione della risposta (ID o hostname)
        char* response = NULL;
        if (strcmp(buffer, "ID") == 0) {
            response = get_unique_id();
        } else if (strcmp(buffer, "HOSTNAME") == 0) {
            response = get_hostname();
        } else {
            response = "Comando non riconosciuto";
        }

        // Invio della risposta al client
        ssize_t sent_len = sendto(sockfd, response, strlen(response), 0, (struct sockaddr*)&client_addr, addr_len);
        if (sent_len < 0) {
            perror("sendto");
            continue;
        }
        if(isVerbose) printf("Risposta inviata: %s\n", response);
    }
    close(sockfd);
    exit(EXIT_SUCCESS);
}


