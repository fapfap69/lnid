/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Server che ritorna l'hostname ad una richiesta UDP

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
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <errno.h>


#ifdef __linux__
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#elif defined(__APPLE__)
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>  // Necessario per LLADDR
#include <net/if_dl.h>
#endif

#define DEFAULT_PORT 16969 // Porta su cui ascoltare
#define BUFFER_SIZE 1024

// Variabili Globali
int theListeningPort = DEFAULT_PORT;
char theEthernetMAC[50] = "eth0";
int isVerbose = 0;

// Funzione per stampare l'uso del programma
void print_usage() {
    printf("***  Local Network Identity Discovery Server  ***\n");
    printf(" Auth: A.Franco - INFN Bari Italy \n");
    printf(" Date : 28/11/2024 -  Ver. 1.1    \n\n");
    printf("Utilizzo: lnidd -e <ethernet> -p <porta> -v -h\n");
    printf("  -e <ethernet>     : specifica la scheda ethernet da utilizzare  (default=eth0)\n");
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
        else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            strncpy(theEthernetMAC, argv[i + 1], 49);
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
        printf("  Ethernet: %s\n", theEthernetMAC);
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

// Funzione per ottenere il MAC address da usare come ID
char *get_macaddr_id() {
    static char id[256];
    unsigned char *mac = NULL;

#ifdef __linux__
    int sock;
    struct ifreq ifr;

    // Crea un socket di tipo AF_INET
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("Errore durante la creazione del socket");
        exit(EXIT_FAILURE);
    }

    // Copia il nome dell'interfaccia nella struttura ifreq
    strncpy(ifr.ifr_name, theEthernetMAC, IFNAMSIZ - 1);

    // Usa ioctl per ottenere il MAC address
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        perror("Errore durante l'ottenimento del MAC address");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Estrae il MAC address dalla struttura ifreq
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    // Stampa il MAC address in formato esadecimale
    if(isVerbose) printf("MAC address di %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ifr.ifr_name,
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);

    close(sock);

#elif defined(__APPLE__)
    struct ifaddrs *ifaddr, *ifa;
    
    // Ottieni tutte le informazioni sulle interfacce di rete
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // Scorri le interfacce
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // Controlla se l'interfaccia corrisponde a quella richiesta
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        // Verifica se l'interfaccia è di tipo AF_LINK (incluso il MAC address)
        if (ifa->ifa_addr->sa_family == AF_LINK && strcmp(ifa->ifa_name, theEthernetMAC) == 0) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *) ifa->ifa_addr;
            mac = (unsigned char *)sdl->sdl_data + 6;  // I primi 6 byte sono l'indirizzo MAC

            // Stampa l'indirizzo MAC in formato esadecimale
            printf("MAC address di %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   ifa->ifa_name,
                   mac[0], mac[1], mac[2],
                   mac[3], mac[4], mac[5]);
            break;
        }
    }
    freeifaddrs(ifaddr);
#else
    fprintf(stderr, "Questo programma non è supportato su questo sistema operativo.\n");
    exit(EXIT_FAILURE);
#endif
    if(mac == NULL) {
        snprintf(id, sizeof(id), "00:00:00:00:00:00");    
    } else {
        snprintf(id, sizeof(id), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);    
    }
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
        } else if (strcmp(buffer, "MAC") == 0) {
            response = get_macaddr_id();
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


