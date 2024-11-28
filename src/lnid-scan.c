/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Scanner che ritorna tutti i server LNID su di una sottorete

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
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

#define DEFAULT_PORT 16969 // Porta UDP del demone
#define BUFFER_SIZE 1024
#define TIMEOUT_SEC 0  // Timeout in secondi
#define TIMEOUT_USEC 50000 // Timeout in microsecondi

// Variabili Globali
int theListeningPort = DEFAULT_PORT;
int isVerbose = 0;
int theDelay = 150; // milliseconds
char theSubNet[50] = "192.168.0.0";
char theNetMask[50] = "255.255.255.0";
char theMessage[25] = "HOSTNAME";
char theResponse[255];
time_t theTimeOutSec = TIMEOUT_SEC;
useconds_t theTimeOutUSec = TIMEOUT_USEC;

// Funzione per stampare l'uso del programma
void print_usage() {
    printf("***  Local Network Identity Discovery Scanner  ***\n");
    printf(" Auth: A.Franco - INFN Bari Italy \n");
    printf(" Date : 28/11/2024 -  Ver. 0.1    \n\n");
    printf("Utilizzo: lnid-scan -s <indirizzo_subnet> -p <porta> -t <milliseconds> -o <milliseconds> -d -v -h\n");
    printf("  -s <indirizzo_subnet> : specifica la subnet\n");
    printf("  -p <porta>        : specifica la porta da utilizzare (default=16969)\n");
    printf("  -t <milliseconds> : ritardo fra scansioni successive (default=50\n");
    printf("  -o <milliseconds> : timeout in ricezione (default=100\n");
    printf("  -d                : ritorna il PID\n");
    printf("  -v                : attiva la modalità verbose\n");
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
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            strlcpy(theSubNet, argv[i + 1], 49); 
            i++; // Salta l'argomento dell'IP
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            theListeningPort = atoi(argv[i + 1]);
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            theDelay = atoi(argv[i + 1]);
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            long mills = atoi(argv[i + 1]);
            theTimeOutSec = (time_t)(mills / 1000);
            theTimeOutUSec = (useconds_t)((mills % 1000) * 1000);
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-v") == 0) {
            isVerbose = 1;
        }
        else if (strcmp(argv[i], "-d") == 0) {
            strcpy(theMessage,"ID");
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
    if (*theSubNet == '\0' || theListeningPort == 0) {
        printf("Errore: SubNet o porta errata.\n");
        exit(EXIT_FAILURE); // Error exit code
    }
    if(theTimeOutSec == 0 && theTimeOutUSec == 0) {
        theTimeOutSec = TIMEOUT_SEC;
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
            printf("Errore: SubNet %s non ammessa.\n", theSubNet);
            exit(EXIT_FAILURE); // Error exit code
            break;
    }

    // Stampa delle informazioni di configurazione
    if(isVerbose) {
        printf("Configurazione:\n");
        printf("  Subnet: %s\n", theSubNet);
        printf("  Mask: %s\n", theNetMask);
        printf("  Porta: %d\n", theListeningPort);
        printf("  Ritardo: %d\n", theDelay);
        printf("  Timeout: %ld\n", (long)theTimeOutSec * 1000 + ((long)theTimeOutUSec/1000));
        printf("  Richiesta: %s\n", theMessage);
        printf("  Modalità verbose attivata\n");
    }
    return;
} 


// Funzione per inviare una richiesta UDP a un dato IP e porta
int send_udp_request(const char *ip_address) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct timeval timeout;
    char buffer[BUFFER_SIZE];

    // Creazione del socket UDP
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    // Imposta il timeout per il socket
    timeout.tv_sec = theTimeOutSec;
    timeout.tv_usec = theTimeOutUSec;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Errore nell'impostazione del timeout");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Impostazione dell'indirizzo del server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(theListeningPort);
    server_addr.sin_addr.s_addr = inet_addr(ip_address);

    // Invio di una richiesta al demone (es. "ID" o "HOSTNAME")
    if (sendto(sockfd, theMessage, strlen(theMessage), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("sendto");
        close(sockfd);
        return -1;
    }
    if(isVerbose) printf("Invio richiesta a %s: %s\n", ip_address, buffer);

    // Ricezione della risposta dal demone
    ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (recv_len < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            if(isVerbose) printf("Timeout raggiunto per %s\n", ip_address);
        } else {
            if(isVerbose) printf("Errore durante la ricezione per %s", ip_address);
        }
        // Nessuna risposta ricevuta
        close(sockfd);
        return 0;
    }

    buffer[recv_len] = '\0';
    if(isVerbose) printf("Risposta da %s: %s\n", ip_address, buffer);
    close(sockfd);
    strlcpy(theResponse, buffer, 254);
    return 1;  // Risposta ricevuta
}

// Funzione per generare gli indirizzi IP in una sottorete
void scan_subnet(const char *subnet, const char *mask) {
    struct in_addr subnet_addr, mask_addr;
    inet_pton(AF_INET, subnet, &subnet_addr);
    inet_pton(AF_INET, mask, &mask_addr);

    // Maschera inversa per ottenere la gamma degli IP
    unsigned int start_ip = ntohl(subnet_addr.s_addr) & ntohl(mask_addr.s_addr);
    unsigned int end_ip = start_ip | ~ntohl(mask_addr.s_addr);

    if(isVerbose) printf("Scansione della sottorete %s con maschera %s...\n", subnet, mask);

    // Scansione della gamma di indirizzi IP
    for (unsigned int ip = start_ip + 1; ip < end_ip; ip++) {
        // Conversione da int a stringa IP
        struct in_addr ip_addr;
        ip_addr.s_addr = htonl(ip);
        char ip_string[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_addr, ip_string, INET_ADDRSTRLEN);

        // Invia la richiesta UDP a questo IP
        if(send_udp_request(ip_string) == 1) { // ok
            printf("%s %s\n",ip_string, theResponse);
        }

        // Inserisce un delay 
        usleep(theDelay * 1000);
    }
}

int main(int argc, char *argv[]) {

    // Decodifica la riga di comando 
    decode_cmdline(argc, argv);

    // Esegui lo scan della sottorete
    scan_subnet(theSubNet, theNetMask);

    exit(EXIT_SUCCESS);
}

