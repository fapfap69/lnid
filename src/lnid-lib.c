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

#if defined(__APPLE__)
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/ethernet.h>  // Necessario per LLADDR
#include <net/if_dl.h>
#endif


int isVerbose = 0;

// --- The SSL support
#include "lnid-ssl.c"

// --- Web server ---
#define DEFAULT_PORT 16969 // Porta su cui ascoltare
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100
#define TIMEOUT_SEC 2  // Timeout in secondi
#define TIMEOUT_USEC 0 // Timeout in microsecondi
#define TRUE 1
#define FALSE 0

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
char *get_macaddr_id(char *theEthernetMAC) {
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
//
size_t readAllFile(char *fileName, char *buffer) {
    size_t fsize = 0;
    FILE *fp = fopen(fileName, "rb");
    if(fp == NULL) return(fsize);
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET); 
    if(fsize > BUFFER_SIZE) {
        fprintf(stdout,"readAllFile() : file eccedente la massima dimensione dei buffer !"); 
        fsize = 0;
    } else {
        size_t re = fread(buffer, 1, fsize, fp);
        if(re != fsize) {
            fprintf(stdout,"readAllFile() : errore in lettura (%lu->%lu)!\n",fsize,re); 
            fsize = 0;
        } 
    }
    fclose(fp);
    return(fsize);
}

int writeAllFile(char *fileName, char *buffer, size_t len) {
    FILE *fp = fopen(fileName, "w");
    if(fp == NULL) return(FALSE);
    size_t wr = fwrite(buffer, 1, len, fp);
    fclose(fp);
    if(wr != len) return(FALSE);
    else return(TRUE);
}

void creaIlSocket(int *sockfd, struct timeval *timeout, struct sockaddr_in *server_addr, 
                    int theListeningPort, const char *theServerIp ) {

    // Creazione del socket UDP
    if ((*sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if(isVerbose) fprintf(stdout,"Socket creato ...\n");

    // Imposta il timeout per il socket
    timeout->tv_sec = TIMEOUT_SEC;
    timeout->tv_usec = TIMEOUT_USEC;
    if (setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof(*timeout)) < 0) {
        perror("Errore nell'impostazione del timeout");
        close(*sockfd);
        exit(EXIT_FAILURE);
    }

    // Inizializzazione dell'indirizzo del server
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(theListeningPort);
    server_addr->sin_addr.s_addr = inet_addr(theServerIp);
    return;
}

void creaIlServerSocket(int *sockfd, struct sockaddr_in *server_addr, 
                        fd_set *read_fds, int theListeningPort ) {

    // Creazione del socket UDP
    if ((*sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if(isVerbose) fprintf(stdout,"Socket creato \n");

    // Inizializzazione della struttura dell'indirizzo del server
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = INADDR_ANY; // Accetta connessioni su tutte le interfacce
    server_addr->sin_port = htons(theListeningPort);

    // Binding del socket all'indirizzo e alla porta
    if (bind(*sockfd, (const struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        perror("bind");
        close(*sockfd);
        exit(EXIT_FAILURE);
    }

    FD_ZERO(read_fds);
    FD_SET(*sockfd, read_fds);
    return;
}

// ---- Ricezione della risposta con eventuale decriptatura
//
int rxData(int sockfd, char *buffer, size_t *recv_len, 
            char *ip_address, EVP_PKEY *keypair) {

    *recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (*recv_len < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            if(isVerbose) fprintf(stdout,"Timeout raggiunto per %s\n", ip_address);
        } else {
            if(isVerbose) fprintf(stdout,"Errore durante la ricezione per %s", ip_address);
        }
        // Nessuna risposta ricevuta
        close(sockfd);
        return(FALSE);
    }
    buffer[*recv_len] = '\0'; 
    if(keypair != NULL) { // i dati sono criptati 
        unsigned char *decr;
        size_t lm;  
        if(doDecrypt(keypair, (const unsigned char *)buffer, *recv_len,
                     &decr, &lm) == FALSE) {
            fprintf(stderr,"rxData() : Errore di decifratura!");
            return(FALSE);
        }      
        if(decr != NULL) {
            memcpy(buffer, decr, lm); 
            buffer[lm] = '\0';
            *recv_len = lm;
            OPENSSL_free(decr);
        }
    }
    if(isVerbose) fprintf(stdout,"rxData() :Ricevuti bytes %lu = [%.8s...]\n", *recv_len , buffer);
    return(TRUE);
}   

// ---- INvio della risposta con eventuale criptatura
//
int txData(int sockfd, char *buffer, size_t *txlen, 
                char *ip_address, struct sockaddr_in server_addr, 
                EVP_PKEY *keypair) {

    ssize_t sentLen = 0;
    if(keypair != NULL) { // bisogna crittografare 
        unsigned char *decr;
        size_t lm;
        if(doEncrypt(keypair, (const unsigned char *)buffer, *txlen, &decr, &lm) == FALSE) {
            fprintf(stderr,"txData() : Errore di cifratura!");
            return(FALSE);
        }
        if(decr != NULL) {
            memcpy(buffer, decr, lm);
            buffer[lm] = '\0';
            *txlen = lm;
            OPENSSL_free(decr);
        }
    }
    sentLen = sendto(sockfd, buffer, *txlen, 0, (const struct sockaddr *)(&server_addr), sizeof(server_addr));
    if(sentLen <= 0) {
        fprintf(stderr,"txData() : Errore di trasmissione %zd bytes in spedizione, 0 inviati!", sentLen);
    }
    *txlen = sentLen;
    if(isVerbose) fprintf(stdout,"txData() : Trasmessi byte = %lu [%.20s...]\n", *txlen, buffer);
    return(TRUE);
}

// Bussa al server  
//
//
int clientKnock(int sockfd, char *pubPEMKey, size_t *keylen, char *theServerIp, EVP_PKEY *keypair,
                OSSL_LIB_CTX *libctx, struct sockaddr_in server_addr, char *theMessage) {
    char buf[10];

    if(txData(sockfd, pubPEMKey, keylen, theServerIp, server_addr, NULL) == FALSE) { // chiave pubblica
        fprintf(stderr,"Errore di trasmissione !\n");
        return(FALSE);
    }
    if(isVerbose) fprintf(stdout,"Chiave pubblica inviata a:%s \n", theServerIp);
    if(rxData(sockfd, pubPEMKey, keylen, theServerIp, NULL) == FALSE) { // server pub key ricevuta
        return(FALSE);
    }
    EVP_PKEY *keyServPub = setupPublicKey(libctx, NULL, TRUE, "/tmp/pubserverkey.pem",
                                         (const unsigned char *)pubPEMKey, *keylen); // memorizza la chiave pubblica
    if(keyServPub == NULL) { 
        fprintf(stderr,"Chiave pubblica non valida !\n");
        return(FALSE);
    }
    if(isVerbose) fprintf(stdout,"Chiave  pubblica ricevuta da:%s \n", theServerIp);
        
    size_t txlen = strlen((const char *)theMessage);
    if(txData(sockfd, (char *)theMessage, &txlen, theServerIp, server_addr, keyServPub) == FALSE) {
        fprintf(stderr,"Errore di trasmissione !\n");
        return(FALSE);
    }
    if(rxData(sockfd, pubPEMKey, keylen, theServerIp, keypair) == FALSE) {  // leggi la risposta 
        fprintf(stderr,"Errore di ricezione !\n");
        return(FALSE);
    }
    //printf(">>> %lu %lu %lu \n\n", keypair,pubPEMKey); 
    txlen = 3;
    strcpy(buf,"Bye");
    if(txData(sockfd, buf, &txlen, theServerIp, server_addr, NULL) == FALSE) {
        fprintf(stderr,"Errore di trasmissione !\n");
        return(FALSE);
    }
    return(TRUE);
}

#endif
// --------  EOF ---------