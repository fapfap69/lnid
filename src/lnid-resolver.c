/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Resolver daemon che aggiorna automaticamente /etc/hosts

 Copyright (c) 2024 Antonio Franco

 Questo programma è rilasciato sotto la licenza Creative Commons Attribuzione 4.0 Internazionale (CC BY 4.0).
 Puoi condividere, copiare, distribuire e modificare il programma, a condizione di dare il dovuto credito all'autore originale.

 Licenza completa: https://creativecommons.org/licenses/by/4.0/
 
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1

 ---------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include "lnid-lib.h"
#include "lnid-ssl.h"

// Configurazione
#define HOSTS_FILE "/etc/hosts"
#define HOSTS_BACKUP "/etc/hosts.lnid.bak"
#define SCAN_INTERVAL 300  // 5 minuti
#define ENTRY_TTL 1800     // 30 minuti
#define MAX_ENTRIES 100
#define LNID_MARKER "# LNID-MANAGED"

// Struttura per cache entries
typedef struct {
    char hostname[256];
    char ip[INET_ADDRSTRLEN];
    time_t last_seen;
    int active;
} HostEntry;

// Variabili globali
extern int isVerbose;
int isDaemon = 1;
int scanInterval = SCAN_INTERVAL;
char subnet[50] = "192.168.1";
int theListeningPort = DEFAULT_PORT;
int isRSA = 0;
HostEntry hostCache[MAX_ENTRIES];
int cacheSize = 0;
volatile int running = 1;

void print_usage() {
    fprintf(stdout,"***  LNID Resolver Daemon  ***\n");
    fprintf(stdout," Auth: A.Franco - INFN Bari Italy \n");
    fprintf(stdout," Date : 07/07/2025 -  Ver. 2.1    \n\n");
    fprintf(stdout,"Utilizzo: lnid-resolver -s <subnet> -i <interval> -f -v -h\n");
    fprintf(stdout,"  -s <subnet>       : subnet da scansionare (default=192.168.1)\n");
    fprintf(stdout,"  -i <interval>     : intervallo scansione in secondi (default=300)\n");
    fprintf(stdout,"  -p <porta>        : porta LNID (default=16969)\n");
    fprintf(stdout,"  -f                : esegui in foreground (non daemon)\n");
    fprintf(stdout,"  -c                : usa modalità cifrata\n");
    fprintf(stdout,"  -v                : modalità verbose\n");
    fprintf(stdout,"  -h                : visualizza help\n");
    return;
}

void signal_handler(int sig) {
    if(isVerbose) fprintf(stdout, "\nRicevuto segnale %d, terminazione...\n", sig);
    running = 0;
}

// Backup del file hosts originale
int backup_hosts_file() {
    FILE *src = fopen(HOSTS_FILE, "r");
    if (!src) {
        fprintf(stderr, "Errore apertura %s: %s\n", HOSTS_FILE, strerror(errno));
        return 0;
    }
    
    FILE *dst = fopen(HOSTS_BACKUP, "w");
    if (!dst) {
        fclose(src);
        fprintf(stderr, "Errore creazione backup: %s\n", strerror(errno));
        return 0;
    }
    
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), src)) {
        fputs(buffer, dst);
    }
    
    fclose(src);
    fclose(dst);
    return 1;
}

// Rimuove entries LNID scadute dal file hosts
int cleanup_hosts_file() {
    FILE *src = fopen(HOSTS_FILE, "r");
    if (!src) return 0;
    
    FILE *tmp = fopen("/tmp/hosts.tmp", "w");
    if (!tmp) {
        fclose(src);
        return 0;
    }
    
    char line[1024];
    int skip_section = 0;
    
    while (fgets(line, sizeof(line), src)) {
        if (strstr(line, LNID_MARKER)) {
            skip_section = 1;
            continue;
        }
        if (skip_section && (line[0] == '\n' || line[0] == '#')) {
            skip_section = 0;
        }
        if (!skip_section) {
            fputs(line, tmp);
        }
    }
    
    fclose(src);
    fclose(tmp);
    
    return rename("/tmp/hosts.tmp", HOSTS_FILE) == 0;
}

// Aggiorna il file hosts con le entries attive
int update_hosts_file() {
    cleanup_hosts_file();
    
    FILE *hosts = fopen(HOSTS_FILE, "a");
    if (!hosts) {
        fprintf(stderr, "Errore apertura %s per scrittura\n", HOSTS_FILE);
        return 0;
    }
    
    time_t now = time(NULL);
    int active_entries = 0;
    
    fprintf(hosts, "\n%s START\n", LNID_MARKER);
    
    for (int i = 0; i < cacheSize; i++) {
        if (hostCache[i].active && (now - hostCache[i].last_seen) < ENTRY_TTL) {
            fprintf(hosts, "%s\t%s\t# LNID auto-discovered\n", 
                   hostCache[i].ip, hostCache[i].hostname);
            active_entries++;
        }
    }
    
    fprintf(hosts, "%s END\n", LNID_MARKER);
    fclose(hosts);
    
    if(isVerbose) fprintf(stdout, "Aggiornate %d entries in %s\n", active_entries, HOSTS_FILE);
    return 1;
}

// Genera hostname unico per conflitti LNID multipli
void make_unique_lnid_hostname(char *hostname, const char *original, const char *ip) {
    // Estrae ultimo ottetto IP per suffisso
    const char *last_dot = strrchr(ip, '.');
    if (last_dot) {
        snprintf(hostname, 256, "%s-lnid%s", original, last_dot + 1);
    } else {
        snprintf(hostname, 256, "%s-lnid", original);
    }
}

// Aggiunge/aggiorna entry nella cache (solo conflitti LNID)
void update_cache_entry(const char *ip, const char *hostname) {
    time_t now = time(NULL);
    char final_hostname[256];
    int has_lnid_conflict = 0;
    
    // Cerca conflitti con altri server LNID (stesso hostname, IP diverso)
    for (int i = 0; i < cacheSize; i++) {
        if (strcmp(hostCache[i].hostname, hostname) == 0 && 
            strcmp(hostCache[i].ip, ip) != 0 && 
            hostCache[i].active) {
            has_lnid_conflict = 1;
            break;
        }
    }
    
    // Risolvi conflitti LNID generando hostname unico
    if (has_lnid_conflict) {
        make_unique_lnid_hostname(final_hostname, hostname, ip);
        if(isVerbose) fprintf(stdout, "LNID conflict resolved: %s -> %s\n", hostname, final_hostname);
    } else {
        strncpy(final_hostname, hostname, sizeof(final_hostname) - 1);
        final_hostname[sizeof(final_hostname) - 1] = '\0';
    }
    
    // Cerca entry esistente per questo IP
    for (int i = 0; i < cacheSize; i++) {
        if (strcmp(hostCache[i].ip, ip) == 0) {
            strncpy(hostCache[i].hostname, final_hostname, sizeof(hostCache[i].hostname) - 1);
            hostCache[i].last_seen = now;
            hostCache[i].active = 1;
            return;
        }
    }
    
    // Aggiungi nuova entry se c'è spazio
    if (cacheSize < MAX_ENTRIES) {
        strncpy(hostCache[cacheSize].hostname, final_hostname, sizeof(hostCache[cacheSize].hostname) - 1);
        strncpy(hostCache[cacheSize].ip, ip, sizeof(hostCache[cacheSize].ip) - 1);
        hostCache[cacheSize].last_seen = now;
        hostCache[cacheSize].active = 1;
        cacheSize++;
        if(isVerbose) fprintf(stdout, "New host discovered: %s -> %s\n", final_hostname, ip);
    }
}

// Scansiona la subnet per server LNID
void scan_network() {
    if(isVerbose) fprintf(stdout, "Scansione rete %s...\n", subnet);
    
    EVP_PKEY *pairKey = NULL;
    if(isRSA) {
        initSecureTempFiles();
        pairKey = generateRsaKeyPair(KEY_SIZE);
        if(pairKey) {
            storeKeyInPEM(pairKey, PUBKEYFILEC, EVP_PKEY_PUBLIC_KEY, NULL);
            storeKeyInPEM(pairKey, PRIVKEYFILEC, EVP_PKEY_KEYPAIR, NULL);
        }
    }
    
    // Costruisce subnet completa
    char full_subnet[64];
    snprintf(full_subnet, sizeof(full_subnet), "%s.0", subnet);
    
    struct in_addr subnet_addr, mask_addr;
    inet_pton(AF_INET, full_subnet, &subnet_addr);
    inet_pton(AF_INET, "255.255.255.0", &mask_addr);
    
    unsigned int start_ip = ntohl(subnet_addr.s_addr) & ntohl(mask_addr.s_addr);
    unsigned int end_ip = start_ip | ~ntohl(mask_addr.s_addr);
    
    char response[RESPONSE_SIZE];
    int discoveries = 0;
    
    for (unsigned int ip = start_ip + 1; ip < end_ip && ip < start_ip + 254; ip++) {
        struct in_addr ip_addr;
        ip_addr.s_addr = htonl(ip);
        char ip_string[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_addr, ip_string, INET_ADDRSTRLEN);
        
        if(sendUdpRequest(ip_string, response, pairKey, theListeningPort, "HOSTNAME", isRSA)) {
            if(strlen(response) > 0 && strcmp(response, "Non autorizzato") != 0) {
                update_cache_entry(ip_string, response);
                discoveries++;
            }
        }
        usleep(50000); // 50ms delay
    }
    
    if(isRSA && pairKey) {
        EVP_PKEY_free(pairKey);
        cleanupSecureTempFiles();
    }
    
    if(isVerbose) fprintf(stdout, "Scansione completata: %d host scoperti\n", discoveries);
}

// Diventa daemon
void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    
    if (setsid() < 0) exit(EXIT_FAILURE);
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    
    umask(0);
    chdir("/");
    
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
}

// Decodifica la command line e setta le variabili
void decode_cmdline(int argc, char *argv[]) {
    // Parsing argomenti
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            strncpy(subnet, argv[i + 1], sizeof(subnet) - 1);
            subnet[sizeof(subnet) - 1] = '\0';
            i++;
        }
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            scanInterval = atoi(argv[i + 1]);
            if (scanInterval < 60) scanInterval = 60; // Minimo 1 minuto
            i++;
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            int port = atoi(argv[i + 1]);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Errore: porta deve essere tra 1 e 65535\n");
                exit(EXIT_FAILURE);
            }
            theListeningPort = port;
            i++;
        }
        else if (strcmp(argv[i], "-f") == 0) {
            isDaemon = 0;
        }
        else if (strcmp(argv[i], "-c") == 0) {
            isRSA = 1;
        }
        else if (strcmp(argv[i], "-v") == 0) {
            isVerbose = 1;
        }
        else if (strcmp(argv[i], "-h") == 0) {
            print_usage();
            exit(EXIT_SUCCESS);
        }
        else {
            fprintf(stderr, "Opzione non valida: %s\n", argv[i]);
            print_usage();
            exit(EXIT_FAILURE);
        }
    }
    
    // Stampa configurazione se verbose
    if(isVerbose) {
        fprintf(stdout, "Configurazione:\n");
        fprintf(stdout, "  Subnet: %s\n", subnet);
        fprintf(stdout, "  Intervallo: %d secondi\n", scanInterval);
        fprintf(stdout, "  Porta: %d\n", theListeningPort);
        fprintf(stdout, "  Modalità daemon: %s\n", isDaemon ? "attiva" : "disattiva");
        fprintf(stdout, "  Modalità cifrata: %s\n", isRSA ? "attiva" : "disattiva");
        fprintf(stdout, "  Modalità verbose: attiva\n");
    }
    return;
}

int main(int argc, char *argv[]) {
    // Decodifica argomenti
    decode_cmdline(argc, argv);
    
    // Controllo permessi root
    if (geteuid() != 0) {
        fprintf(stderr, "Errore: sono necessari privilegi root per modificare %s\n", HOSTS_FILE);
        exit(EXIT_FAILURE);
    }
    
    // Backup file hosts
    if (!backup_hosts_file()) {
        fprintf(stderr, "Errore: impossibile creare backup di %s\n", HOSTS_FILE);
        exit(EXIT_FAILURE);
    }
    
    // Setup segnali
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (isDaemon) {
        daemonize();
    }
    
    if(isVerbose && !isDaemon) fprintf(stdout, "LNID Resolver avviato - subnet: %s, intervallo: %ds\n", 
                         subnet, scanInterval);
    
    // Loop principale
    while (running) {
        scan_network();
        update_hosts_file();
        
        // Sleep con controllo interruzione
        for (int i = 0; i < scanInterval && running; i++) {
            sleep(1);
        }
    }
    
    // Cleanup finale
    cleanup_hosts_file();
    if(isVerbose) fprintf(stdout, "LNID Resolver terminato\n");
    
    return EXIT_SUCCESS;
}