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
#include <sys/select.h>
#include <net/if.h>

#if defined(__APPLE__)
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/ethernet.h>  // Necessario per LLADDR
#include <net/if_dl.h>
#endif

#include "lnid-lib.h"
#include "lnid-ssl.h"
#include <signal.h>

// Gestore segnali per cleanup
void signal_handler(int sig) {
    if(isVerbose) fprintf(stdout, "\nRicevuto segnale %d, cleanup in corso...\n", sig);
    if(isRSA) {
        cleanupSecureTempFiles();
    }
    exit(EXIT_SUCCESS);
}

// --- connection states ---
#define ST_NOOSSL 0
#define ST_ACCEPTED 1
#define ST_SSLHANDSHAKE 2
#define ST_SERVED 3
#define ST_DESTROY 4

typedef struct {
    struct sockaddr_in addr;
    socklen_t addr_len;
    int state;
    EVP_PKEY *pubKey;
    time_t last_activity;  // Per timeout inattività
} Client;

// Variabili Globali
extern int isVerbose;

int theListeningPort = DEFAULT_PORT;
char theEthernetMAC[50] = "eth0";

int isRSA = 0; // Is the comunication RSA
EVP_PKEY *privateKey = NULL;
EVP_PKEY *publicKey = NULL;
EVP_PKEY *pairKey = NULL;
OSSL_LIB_CTX *osslLibCtx = NULL;

// Funzione per stampare l'uso del programma
void print_usage() {
    fprintf(stdout,"***  Local Network Identity Discovery Server  ***\n");
    fprintf(stdout," Auth: A.Franco - INFN Bari Italy \n");
    fprintf(stdout," Date : 06/12/2024 -  Ver. 2.0    \n\n");
    fprintf(stdout,"Utilizzo: lnidd -e <ethernet> -p <porta> -v -h\n");
    fprintf(stdout,"  -e <ethernet>     : specifica la scheda ethernet da utilizzare  (default=eth0)\n");
    fprintf(stdout,"  -p <porta>        : specifica la porta da utilizzare  (default=16969)\n");
    fprintf(stdout,"  -c                : attiva la modalità cifrata\n");
    fprintf(stdout,"  -v                : attiva la modalità verbose\n");
    fprintf(stdout,"  -h                : visualizza l'help\n ");
    return;
}

// Decodifica la command line e setta le variabili
void decode_cmdline(int argc, char *argv[]) {
 
    // Elaborazione degli argomenti
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            int port = atoi(argv[i + 1]);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Errore: porta deve essere tra 1 e 65535\n");
                exit(EXIT_FAILURE);
            }
            theListeningPort = port;
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            strncpy(theEthernetMAC, argv[i + 1], sizeof(theEthernetMAC) - 1);
            theEthernetMAC[sizeof(theEthernetMAC) - 1] = '\0';
            i++; // Salta l'argomento della porta
        }
        else if (strcmp(argv[i], "-c") == 0) {
            isRSA = 1;
        }
        else if (strcmp(argv[i], "-v") == 0) {
            isVerbose = 1;
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
    if (theListeningPort == 0) {
        fprintf(stdout,"Errore: porta errata.\n");
        exit(EXIT_FAILURE); // Error exit code
    }

    // Stampa delle informazioni di configurazione
    if(isVerbose) {
        fprintf(stdout,"Configurazione:\n");
        fprintf(stdout,"  Ethernet: %s\n", theEthernetMAC);
        fprintf(stdout,"  Porta: %d\n", theListeningPort);
        fprintf(stdout,"  Modalità cifrata %s\n", isRSA == 0 ? "disattivata" : "attivata" );
        fprintf(stdout,"  Modalità verbose attivata\n");
    }
    return;
} 

void buildTheResponse(char *message) {
    if (strcmp(message, "ID") == 0) {
        strncpy(message, get_unique_id(), BUFFER_SIZE - 1);
        message[BUFFER_SIZE - 1] = '\0';
    } else if (strcmp(message, "MAC") == 0) {
        strncpy(message, get_macaddr_id(theEthernetMAC), BUFFER_SIZE - 1);
        message[BUFFER_SIZE - 1] = '\0';
    } else if (strcmp(message, "HOSTNAME") == 0) {
        strncpy(message, get_hostname(), BUFFER_SIZE - 1);
        message[BUFFER_SIZE - 1] = '\0';
    } else {
        strncpy(message, "Comando non riconosciuto", BUFFER_SIZE - 1);
        message[BUFFER_SIZE - 1] = '\0';
    }
    return;
}

void handleClientMessage(Client *client, char *message, size_t *bytes_received ) {
    if(isVerbose) fprintf(stdout," Stato:%d Ricevuto messaggio da %s:%d\n",client->state, inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
    
    unsigned char *decr;
    size_t lm;
    char *passw = NULL;
    static char clientKeyFile[256] = {0};

    switch(client->state) {
        case ST_ACCEPTED: // Abbiamo ricevuto una chiave pubblica
            // Crea file temporaneo sicuro per chiave client
            if (clientKeyFile[0] == '\0') {
                char template_path[256];
                int fd = createSecureTempFile(template_path, clientKeyFile, sizeof(clientKeyFile));
                if (fd == -1) { client->state = ST_DESTROY; return; }
                close(fd);
            }
            if(writeAllFile(clientKeyFile, message, *bytes_received) == FALSE) { exit(EXIT_FAILURE); }
            client->pubKey = loadKeyFromPEM(osslLibCtx, clientKeyFile, passw);
            if(client->pubKey == NULL) { client->state = ST_DESTROY; return; }
            *bytes_received = BUFFER_SIZE; // carica la dimensione massima del buffer pre allocato
            if(readAllFile(PUBKEYFILES, &message, bytes_received) == FALSE) {  // nel buffer la chiave pubblica del server
                client->state = ST_DESTROY;
                break; 
            }
            client->state = ST_SSLHANDSHAKE;
            break;

        case ST_SSLHANDSHAKE: // Adesso si ricevono messaggi criptati
            // printf("=== privata Server --\n");
            // dumpKeyPair(pairKey);
            doDecrypt(pairKey, (const unsigned char *)message, *bytes_received, &decr, &lm);
            if(decr != NULL) memcpy(message, decr, lm); 
            message[lm] = '\0';
            OPENSSL_free(decr);
            buildTheResponse(message); // compone la risposta
            // printf("=== pubblica client --\n");
            // dumpKeyPair(client->pubKey);
            doEncrypt(client->pubKey, (const unsigned char *)message, strlen(message), &decr, &lm); //cripta
            memcpy(message, decr, lm);
            message[lm] = '\0';
            *bytes_received = lm;
            OPENSSL_free(decr);
            client->state = ST_SERVED;
            break;

        case ST_SERVED: // Abbiamo ricevuto una fine transazione 
            if(client->pubKey != NULL) EVP_PKEY_free(client->pubKey);
            client->pubKey = NULL;
            strcpy(message, "Bye"); // La risposta del server 
            *bytes_received = 4;
            client->state = ST_DESTROY;
            break;

        case ST_DESTROY: // we receive message after end. Parrot mode
            break;

        case ST_NOOSSL: // Questo e' il comportamento semplice
            buildTheResponse(message);
            *bytes_received = strlen(message);
            break;

        default: 
            break;
    }
    return;
}

int main(int argc, char *argv[]) {

    char buffer[BUFFER_SIZE];

    // legge la command line 
    decode_cmdline(argc, argv);
    
    // Installa gestore segnali per cleanup
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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
        storeKeyInPEM(pairKey, PUBKEYFILES, EVP_PKEY_PUBLIC_KEY, passphrase);
        storeKeyInPEM(pairKey, PRIVKEYFILES, EVP_PKEY_KEYPAIR, passphrase);
    }
    // Creazione del socket UDP
    int sockfd;
    struct sockaddr_in server_addr;
    fd_set read_fds, temp_fds;
    size_t bytes_received;

    creaIlServerSocket(&sockfd, &server_addr, &read_fds, theListeningPort);
    int max_fd = sockfd;

    Client clients[MAX_CLIENTS];
    int client_count = 0;
    time_t last_cleanup = time(NULL);

    if(isVerbose) fprintf(stdout,"Server UDP in ascolto sulla porta %d...\n", theListeningPort);
    while (1) {
        temp_fds = read_fds;
        
        // Imposta timeout per select
        struct timeval select_timeout;
        select_timeout.tv_sec = 1;
        select_timeout.tv_usec = 0;
        
        // Attendi che ci sia attività su uno dei socket
        int activity = select(max_fd + 1, &temp_fds, NULL, NULL, &select_timeout);
        if (activity < 0) {
            perror("Errore nella chiamata a select");
            break;
        }
        
        // Cleanup periodico ogni 30 secondi
        time_t now = time(NULL);
        if (now - last_cleanup > 30) {
            cleanupRateLimitTable();
            // Cleanup client inattivi
            for (int i = 0; i < client_count; i++) {
                if (clients[i].state != ST_DESTROY && 
                    now - clients[i].last_activity > 300) { // 5 minuti
                    if(clients[i].pubKey != NULL) {
                        EVP_PKEY_free(clients[i].pubKey);
                        clients[i].pubKey = NULL;
                    }
                    clients[i].state = ST_DESTROY;
                    if(isVerbose) fprintf(stdout,"Client timeout: %s:%d\n", 
                        inet_ntoa(clients[i].addr.sin_addr), ntohs(clients[i].addr.sin_port));
                }
            }
            last_cleanup = now;
        }
        
        // Se nessuna attività, continua il loop
        if (activity == 0) continue;
        // Controlla il socket del server
        if (FD_ISSET(sockfd, &temp_fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            // Controllo rate limiting
            if (!checkRateLimit(client_addr.sin_addr.s_addr)) {
                if(isVerbose) fprintf(stdout,"Richiesta bloccata per rate limiting: %s:%d\n", 
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                continue;
            }
            
            // Ricevi il messaggio dal client
            bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&client_addr, &client_len);
            if (bytes_received < 0) {
                perror("Errore durante la ricezione");
                continue;
            }
            
            // Controllo dimensione minima/massima
            if (bytes_received == 0 || bytes_received > BUFFER_SIZE - 1) {
                if(isVerbose) fprintf(stdout,"Dimensione messaggio non valida: %zu\n", bytes_received);
                continue;
            }
            if(isVerbose) {
                fprintf(stdout, "Ricevuto:\n");
                BIO_dump_indent_fp(stdout, buffer, bytes_received, 2);
                fprintf(stdout, "\n");
            }
            buffer[bytes_received] = '\0';
            // Verifica se il client è già noto
            int client_found = 0;
            int freeSlot = -1;
            int idx = -1;
            for (int i = 0; i < client_count; i++) {
                if (clients[i].addr.sin_addr.s_addr == client_addr.sin_addr.s_addr &&
                    clients[i].addr.sin_port == client_addr.sin_port) {
                    client_found = 1;
                    idx = i;
                    break;
                }
                if(clients[i].state == ST_DESTROY) freeSlot = i;
            }
            // Aggiungi il nuovo client se non è noto
            if (!client_found) {
                idx = (freeSlot > -1) ? freeSlot : client_count;
                if(idx < MAX_CLIENTS) {
                    clients[idx].addr = client_addr;
                    clients[idx].addr_len = client_len;
                    clients[idx].state = (isRSA == 0) ? ST_NOOSSL : ST_ACCEPTED;
                    clients[idx].last_activity = time(NULL);
                    clients[idx].pubKey = NULL;
                    if(freeSlot == -1) client_count++;
                    if(isVerbose) fprintf(stdout,"Nuovo client aggiunto: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                } else {
                    if(isVerbose) fprintf(stdout,"Troppi client connessi, richiesta ignorata\n");
                    continue;
                }
            } else {
                // Aggiorna attività client esistente
                clients[idx].last_activity = time(NULL);
            }
            // Controllo stato client valido
            if (clients[idx].state == ST_DESTROY) {
                if(isVerbose) fprintf(stdout,"Messaggio ignorato da client in stato DESTROY\n");
                continue;
            }
            
            // Gestisci il messaggio : buffer In/out !
            handleClientMessage(&clients[idx], buffer, &bytes_received);
//printf(">>>>>> %lu\n\n",bytes_received);
            // Invia la risposta al client
            if(isVerbose) {
                fprintf(stdout, "Risposta del server:\n");
                BIO_dump_indent_fp(stdout, buffer, bytes_received, 2);
                fprintf(stdout, "\n");
            }
            if (sendto(sockfd, buffer, bytes_received, 0, (struct sockaddr *)&client_addr, client_len) < 0) {
                perror("Errore durante l'invio della risposta");
            }
        }
    }
    close(sockfd);

    // Reset up per la cifratura
    if(isRSA) {
        freeRsaKeyPair(pairKey);
        freeRsaKeyPair(privateKey);
        freeRsaKeyPair(publicKey);
        OSSL_LIB_CTX_free(osslLibCtx);
        cleanupSecureTempFiles(); // Pulisce file temporanei
    }
    exit(EXIT_SUCCESS);
}