/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Libreria funzioni

 Copyright (c) 2024 Antonio Franco

 Questo programma è rilasciato sotto la licenza Creative Commons Attribuzione 4.0 Internazionale (CC BY 4.0).
 Puoi condividere, copiare, distribuire e modificare il programma, a condizione di dare il dovuto credito all'autore originale.

 Licenza completa: https://creativecommons.org/licenses/by/4.0/
 
 auth. A.Franco - INFN Bary Italy
 date: 28/11/2024       ver.1.1

 ---------------------------------------------------------
  HISTORY 
  28/11/2024  -  Creation
  06/12/2024  -  Versione 2.0 : OK

 ---------------------------------------------------------
*/
#ifndef __GENERICLIB__
#define __GENERICLIB__

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
#include <time.h>

#if defined(__APPLE__)
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/ethernet.h>  // Necessario per LLADDR
#include <net/if_dl.h>
#endif

//  Variabili globali 
int isVerbose = 0;

// Definizione variabili rate limiting
RateLimitEntry rate_limit_table[MAX_CLIENTS] = {0};
int rate_limit_entries = 0;

// Funzione per controllo rate limiting
// Ritorna TRUE se la richiesta è permessa, FALSE se bloccata
int checkRateLimit(uint32_t ip_addr) {
    time_t now = time(NULL);
    
    // Cerca IP esistente nella tabella
    for (int i = 0; i < rate_limit_entries; i++) {
        if (rate_limit_table[i].ip_addr == ip_addr) {
            // Controlla se la finestra è scaduta
            if (now - rate_limit_table[i].first_request > RATE_LIMIT_WINDOW) {
                // Reset contatore
                rate_limit_table[i].first_request = now;
                rate_limit_table[i].request_count = 1;
                return TRUE;
            }
            // Incrementa contatore
            rate_limit_table[i].request_count++;
            if (rate_limit_table[i].request_count > MAX_REQUESTS_PER_IP) {
                if(isVerbose) {
                    struct in_addr addr;
                    addr.s_addr = ip_addr;
                    fprintf(stdout, "Rate limit superato per IP: %s\n", inet_ntoa(addr));
                }
                return FALSE; // Bloccato
            }
            return TRUE;
        }
    }
    
    // Nuovo IP - aggiungi alla tabella se c'è spazio
    if (rate_limit_entries < MAX_CLIENTS) {
        rate_limit_table[rate_limit_entries].ip_addr = ip_addr;
        rate_limit_table[rate_limit_entries].first_request = now;
        rate_limit_table[rate_limit_entries].request_count = 1;
        rate_limit_entries++;
        return TRUE;
    }
    
    // Tabella piena - cerca slot scaduto
    for (int i = 0; i < rate_limit_entries; i++) {
        if (now - rate_limit_table[i].first_request > RATE_LIMIT_WINDOW) {
            rate_limit_table[i].ip_addr = ip_addr;
            rate_limit_table[i].first_request = now;
            rate_limit_table[i].request_count = 1;
            return TRUE;
        }
    }
    
    return FALSE; // Tabella piena
}

// Pulisce entries scadute dalla tabella rate limiting
void cleanupRateLimitTable() {
    time_t now = time(NULL);
    int write_idx = 0;
    
    for (int read_idx = 0; read_idx < rate_limit_entries; read_idx++) {
        if (now - rate_limit_table[read_idx].first_request <= RATE_LIMIT_WINDOW) {
            if (write_idx != read_idx) {
                rate_limit_table[write_idx] = rate_limit_table[read_idx];
            }
            write_idx++;
        }
    }
    rate_limit_entries = write_idx;
}

// --- The SSL support
#include "lnid-ssl.h"

// --- Web server ---
#define DEFAULT_PORT 16969 // Porta su cui ascoltare
#define BUFFER_SIZE 8192
#define RESPONSE_SIZE 256
#define MAX_CLIENTS 100
#define TIMEOUT_SEC 2  // Timeout in secondi
#define TIMEOUT_USEC 0 // Timeout in microsecondi
#define MAX_REQUESTS_PER_IP 10  // Max richieste per IP per finestra
#define RATE_LIMIT_WINDOW 60    // Finestra rate limiting in secondi
#define CRYPTO_TIMEOUT_SEC 5    // Timeout operazioni crittografiche
#define TRUE 1
#define FALSE 0

// Struttura per rate limiting
typedef struct {
    uint32_t ip_addr;
    time_t first_request;
    int request_count;
} RateLimitEntry;

// Dichiarazioni esterne per rate limiting
extern RateLimitEntry rate_limit_table[MAX_CLIENTS];
extern int rate_limit_entries;

// Funzione per fare il dump di una sockaddr_in
//
void dump_sockaddr_in(const struct sockaddr_in *addr) 
{
    if (addr == NULL) {
        fprintf(stderr, "dump_sockaddr_in() : La struttura sockaddr_in è NULL.\n");
        return;
    }
    // Converti l'indirizzo IP da network byte order a una stringa leggibile
    char ip_str[INET_ADDRSTRLEN]; // Buffer per l'indirizzo IP
    if (inet_ntop(AF_INET, &(addr->sin_addr), ip_str, sizeof(ip_str)) == NULL) {
        fprintf(stderr, "dump_sockaddr_in() : Errore nella conversione dell'indirizzo IP");
        return;
    }
    // Estrai e converte il numero di porta da network byte order
    unsigned short port = ntohs(addr->sin_port);
    // Stampa le informazioni
    fprintf(stdout, "sockaddr_in:\n");
    fprintf(stdout, "  indirizzo variabile in memoria %lu\n", (unsigned long)addr);
    fprintf(stdout, "  Indirizzo IP: %s\n", ip_str);
    fprintf(stdout, "  Porta: %u\n", port);
    fprintf(stdout, "  Famiglia: %s\n", addr->sin_family == AF_INET ? "AF_INET" : "Sconosciuta");
    return;
}

// Funzione per ottenere l'hostname
//
char* get_hostname() 
{
    static char hostname[256];
    if (gethostname(hostname, sizeof(hostname) - 1) == 0) {
        hostname[sizeof(hostname) - 1] = '\0'; // Assicura terminazione
        return hostname;
    } else {
        fprintf(stderr, "get_hostname() : errore ! ");
        return "Unknown";
    }
}

// Funzione per ottenere un ID univoco (può essere il PID o qualsiasi altra cosa)
//
char* get_unique_id() 
{
    static char id[256];
    pid_t pid = getpid();
    if (pid > 0) {
        snprintf(id, sizeof(id), "ID-%d", pid);
    } else {
        strncpy(id, "ID-Unknown", sizeof(id) - 1);
        id[sizeof(id) - 1] = '\0';
    }
    return id;
}

// Funzione per ottenere il MAC address da usare come ID
//
char *get_macaddr_id(char *theEthernetMAC) 
{
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
    if(isVerbose) fprintf(stdout,"MAC address di %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
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
            fprintf(stdout,"MAC address di %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
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

// ---- Legge un intero file in un buffer di memoria
// Ritorna TRUE/ FALSE
//
int readAllFile(char *fileName, char **buffer, size_t *lenBuf) 
{
    int isMemAllocate = FALSE;
    size_t fsize = 0;
    FILE *fp = fopen(fileName, "rb");
    if(fp == NULL) {
        fprintf(stderr,"readAllFile() : errore apertura file %s !", fileName); 
        goto cleanup;
    }
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if((*buffer) == NULL) { // dobbiamo allocare la memoria
        *buffer = malloc(fsize + 2);
        if(*buffer == NULL) {
            fprintf(stderr,"readAllFile() : errore allocazione buffer per il file %s !", fileName); 
            goto cleanup;
        }
        isMemAllocate = TRUE;
    } else {
        if(fsize > *lenBuf) {
            fprintf(stderr,"readAllFile() : file eccedente la massima dimensione dei buffer !"); 
            goto cleanup;
        } 
    }
    // possiamo leggere il file
    size_t re = fread(*buffer, 1, fsize, fp);
    if(re != fsize) {
        fprintf(stderr,"readAllFile() : errore in lettura (%lu->%lu)!\n",fsize,re); 
        goto cleanup;
    } 
    *lenBuf = re;
    fclose(fp);
    return(TRUE);

cleanup:
    *lenBuf = -1;
    if(fp != NULL) fclose(fp);
    if(isMemAllocate == TRUE) { free(*buffer); *buffer = NULL; }
    return(FALSE);
}

//  Scrivi un intero file 
//
int writeAllFile(char *fileName, char *buffer, size_t len) 
{
    FILE *fp = fopen(fileName, "w");
    if(fp == NULL) {
        fprintf(stderr, "writeAllFile() : errore apertura file %s !", fileName);
        return(FALSE);
    }
    size_t wr = fwrite(buffer, 1, len, fp);
    fclose(fp);
    if(wr != len) {
        fprintf(stderr, "writeAllFile() : errore di scrittura su %s !", fileName);
        return(FALSE);
    }
    return(TRUE);
}

// ----- Crea il socket UDP , imposta il timeout e inizializza il IP del server ----
// 
void creaIlSocket(int *sockfd, struct timeval *timeout, 
                    struct sockaddr_in *server_addr, 
                    int theListeningPort, const char *theServerIp ) 
{
    // Validazione parametri
    if (theListeningPort <= 0 || theListeningPort > 65535) {
        fprintf(stderr, "creaIlSocket() : porta non valida: %d\n", theListeningPort);
        exit(EXIT_FAILURE);
    }
    if (theServerIp == NULL) {
        fprintf(stderr, "creaIlSocket() : IP server nullo\n");
        exit(EXIT_FAILURE);
    }

    // Creazione del socket UDP
    if ((*sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "creaIlSocket() : errore nella creazione del socket !");
        exit(EXIT_FAILURE);
    }

    // Imposta il timeout per il socket
    timeout->tv_sec = TIMEOUT_SEC;
    timeout->tv_usec = TIMEOUT_USEC;
    if (setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof(*timeout)) < 0) {
        fprintf(stderr, "creaIlSocket() : Errore nell'impostazione del timeout !");
        close(*sockfd);
        exit(EXIT_FAILURE);
    }

    // Inizializzazione dell'indirizzo del server
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(theListeningPort);
    
    // Validazione e conversione IP
    if (inet_pton(AF_INET, theServerIp, &server_addr->sin_addr) != 1) {
        fprintf(stderr, "creaIlSocket() : indirizzo IP non valido: %s\n", theServerIp);
        close(*sockfd);
        exit(EXIT_FAILURE);
    }
    
    if(isVerbose) fprintf(stdout,"Socket creato su %s:%d !\n",theServerIp,theListeningPort);
    return;
}

// -----  Crea il socket per il server in listening mode -----
//
void creaIlServerSocket(int *sockfd, struct sockaddr_in *server_addr, 
                        fd_set *read_fds, int theListeningPort ) 
{
    // Validazione porta
    if (theListeningPort <= 0 || theListeningPort > 65535) {
        fprintf(stderr, "creaIlServerSocket() : porta non valida: %d\n", theListeningPort);
        exit(EXIT_FAILURE);
    }

    // Creazione del socket UDP
    if ((*sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "creaIlServerSocket() : errore nella creazione del socket !");
        exit(EXIT_FAILURE);
    }

    // Inizializzazione della struttura dell'indirizzo del server
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = INADDR_ANY; // Accetta connessioni su tutte le interfacce
    server_addr->sin_port = htons(theListeningPort);

    // Binding del socket all'indirizzo e alla porta
    if (bind(*sockfd, (const struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        fprintf(stderr, "creaIlServerSocket() : errore nel binding della porta !");
        close(*sockfd);
        exit(EXIT_FAILURE);
    }
    FD_ZERO(read_fds);
    FD_SET(*sockfd, read_fds);
    if(isVerbose) fprintf(stdout,"Server socket creato con successo : in ascolto sulla porta %d!\n", theListeningPort);
    return;
}

// ---- Ricezione della risposta con eventuale decriptatura
//
int rxData(int sockfd, char **buffer, size_t *recv_len, 
            char *ip_address, EVP_PKEY *keypair) 
{
    // per la decriptatura
    unsigned char *decrBuffer = NULL;
    size_t decLen = 0;  

    // Setup del buffer
    int isAllocated = FALSE;
    char *bufferPtr = *buffer; // copia il buffer
    if(bufferPtr == NULL) { // dobbiamo allocare il buffer
        bufferPtr = malloc(*recv_len);
        isAllocated = TRUE;
        if(bufferPtr== NULL) {
            if(isVerbose) fprintf(stderr, "rxData() : Errore di allocazione della memoria !");
            exit(EXIT_FAILURE);
        }
    }
    // legge dal socket con controllo dimensioni
    ssize_t rxLen = recvfrom(sockfd, bufferPtr, *recv_len, 0, NULL, NULL);
    
    // Controllo dimensioni risposta
    if (rxLen > 0 && (rxLen == 0 || rxLen > *recv_len)) {
        if(isVerbose) fprintf(stdout,"Dimensione risposta non valida da %s: %zd\n", ip_address, rxLen);
        goto cleanup;
    }
    if (rxLen < 0) { // Errore
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            if(isVerbose) fprintf(stdout,"Timeout raggiunto per %s\n", ip_address);
        } else {
            if(isVerbose) fprintf(stdout,"Errore durante la ricezione per %s", ip_address);
        }
        // Nessuna risposta ricevuta
        goto cleanup;
    }
    // i dati sono criptati !
    if(keypair != NULL) {  
        if(doDecrypt(keypair,
                    (const unsigned char *)bufferPtr, rxLen,
                    &decrBuffer, &decLen) == FALSE) {
            fprintf(stderr,"rxData() : Errore di decifratura!");
            goto cleanup;
        }
        if(decrBuffer == NULL || decLen > *recv_len) {
            fprintf(stderr,"rxData() : Errore di decifratura o buffer troppo piccolo !");
            goto cleanup;
        }
        // copia i dati in uscita
        memcpy(bufferPtr, decrBuffer, decLen); 
        rxLen = decLen;
        OPENSSL_free(decrBuffer);
    }
    // OK valida il buffer
    bufferPtr[rxLen] = '\0';
    *buffer = bufferPtr; 
    *recv_len = rxLen;
    if(isVerbose) fprintf(stdout,"rxData() :Ricevuti bytes %lu da %s\n", *recv_len , ip_address);
    return(TRUE);

cleanup:
    if(isAllocated == TRUE) free(bufferPtr);
    if(decrBuffer != NULL) OPENSSL_free(decrBuffer);
    close(sockfd);
    return(FALSE);
}   

// ---- INvio della risposta con eventuale criptatura
//
int txData(int sockfd, char *buffer, size_t *txlen, char *ip_address, 
                struct sockaddr_in *server_addr, EVP_PKEY *keypair) 
{
    // per la cifratura
    unsigned char *decBuffer;
    size_t decLen;
    int isAllocated = FALSE;

    // per la spedizione 
    ssize_t toSentLen;
    ssize_t sentLen = 0;
    char *txBuffer = NULL;

    if(keypair != NULL) { // bisogna crittografare 
        if(doEncrypt(keypair, (const unsigned char *)buffer, *txlen, &decBuffer, &decLen) == FALSE) {
            fprintf(stderr,"txData() : Errore di cifratura!");
            return(FALSE);
        }
        if(decBuffer != NULL) {
            txBuffer = (char *)decBuffer;
            toSentLen = decLen;
            isAllocated = TRUE;
        } else {
            return(FALSE);
        }
    } else {
        txBuffer = buffer;
        toSentLen = *txlen;
    }
    sentLen = sendto(sockfd, txBuffer, toSentLen, 0, (const struct sockaddr *)(server_addr), sizeof(*server_addr));
    if(sentLen <= 0) {
        fprintf(stderr,"txData() : Errore di trasmissione %zd bytes in spedizione, 0 inviati!", sentLen);
    }
    // valida l'uscita;
    *txlen = sentLen;
    if(isAllocated == TRUE) OPENSSL_free(decBuffer);
    if(isVerbose) fprintf(stdout,"txData() : Trasmessi byte = %lu a %s\n", *txlen, ip_address);
    return(TRUE);
}

// Bussa al server  
//
//
int clientKnock(int sockfd, char **rxtxBuffer, size_t *buferLen, char *theServerIp, EVP_PKEY *keypair,
                struct sockaddr_in server_addr, char *theMessage) 
{
    char buf[10];
    char *passw = NULL;
    char *txBuffer = *rxtxBuffer;

    if(txData(sockfd, txBuffer, buferLen, theServerIp, &server_addr, NULL) == FALSE) { // chiave pubblica
        fprintf(stderr,"Errore di trasmissione !\n");
        return(FALSE);
    }
    if(isVerbose) fprintf(stdout,"Chiave pubblica inviata a:%s \n", theServerIp);
    if(rxData(sockfd, rxtxBuffer, buferLen, theServerIp, NULL) == FALSE) { // server pub key ricevuta
        return(FALSE);
    }
    // Crea file temporaneo sicuro per chiave server
    static char serverKeyFile[256] = {0};
    if (serverKeyFile[0] == '\0') {
        char template_path[256];
        int fd = createSecureTempFile(template_path, serverKeyFile, sizeof(serverKeyFile));
        if (fd == -1) return FALSE;
        close(fd);
    }
    if(writeAllFile(serverKeyFile, txBuffer, *buferLen) == FALSE) { 
        unlink(serverKeyFile);
        exit(EXIT_FAILURE); 
    }
    EVP_PKEY *keyServPub = loadKeyFromPEM(NULL, serverKeyFile, passw);
    unlink(serverKeyFile); // Rimuovi subito dopo l'uso
    if(keyServPub == NULL) { 
        fprintf(stderr,"Chiave pubblica non valida !\n");
        return(FALSE);
    }
    if(isVerbose) fprintf(stdout,"Chiave  pubblica ricevuta da:%s \n", theServerIp);
    size_t txlen = strlen((const char *)theMessage);
    if(txData(sockfd, theMessage, &txlen, theServerIp, &server_addr, keyServPub) == FALSE) {
        fprintf(stderr,"Errore di trasmissione !\n");
        return(FALSE);
    }
    if(rxData(sockfd, rxtxBuffer, buferLen, theServerIp, keypair) == FALSE) {  // leggi la risposta 
        fprintf(stderr,"Errore di ricezione !\n");
        return(FALSE);
    }
    strcpy(buf,"Bye !");
    txlen = strlen(buf);
    if(txData(sockfd, buf, &txlen, theServerIp, &server_addr, NULL) == FALSE) {
        fprintf(stderr,"Errore di trasmissione !\n");
        return(FALSE);
    }
    return(TRUE);
}

// Funzione per inviare una richiesta UDP a un dato IP e porta
//
int sendUdpRequest(char *ip_address, char *response, EVP_PKEY *pairKey,
                    int theListeningPort, char *theMessage, int isRSA) 
{
    // alloca il buffer
    char *buffer = malloc(BUFFER_SIZE);
    if(buffer == NULL) {
        fprintf(stderr,"Errore di allocazione della memoria !\n");
        return(FALSE);
    }

    int ret = TRUE;
    size_t rxlen = 0;

    // Creazione del socket UDP
    int sockfd;
    struct sockaddr_in server_addr;
    struct timeval timeout;
    creaIlSocket(&sockfd, &timeout, &server_addr, theListeningPort, ip_address);

    if(isRSA == 0) {
        // Invio della richiesta
        if(isVerbose) fprintf(stdout,"sendUdpRequest() : Richesta del '%s' inviata a:%s:%d \n", theMessage, ip_address, theListeningPort);
        rxlen = strlen(theMessage);
        if(txData(sockfd, theMessage, &rxlen, ip_address, &server_addr, NULL) == FALSE) {
            fprintf(stderr,"sendUdpRequest() : Errore di trasmissione !\n");
            ret = FALSE;
        } else {
            rxlen = BUFFER_SIZE; // massima dimensione in ricezione
            if(rxData(sockfd, &buffer, &rxlen, ip_address, NULL) == FALSE) {
               fprintf(stderr,"sendUdpRequest() : Errore di ricezione !\n");
               ret = FALSE;
            }
        }
    } else {    
        rxlen = BUFFER_SIZE; // massima del buffer pre allocato
        if(readAllFile(PUBKEYFILEC, &buffer, &rxlen) == TRUE) {  // nel buffer la chiave pubblica del server
            ret = clientKnock(sockfd, &buffer, &rxlen, ip_address, pairKey, server_addr, theMessage); 
        }
    }
    if(ret == TRUE) {
        buffer[rxlen] = '\0';
        strncpy(response, buffer, RESPONSE_SIZE);
        if(isVerbose) fprintf(stdout,"Risposta da %s: %s\n", ip_address, buffer);
    }
    free(buffer);
    close(sockfd);
    return(ret);
}

#endif
// --------  EOF ---------