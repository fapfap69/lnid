/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Tool gestione entries LNID in /etc/hosts

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define HOSTS_FILE "/etc/hosts"
#define LNID_MARKER "# LNID-MANAGED"

void print_usage() {
    fprintf(stdout,"***  LNID Hosts Manager  ***\n");
    fprintf(stdout," Auth: A.Franco - INFN Bari Italy \n");
    fprintf(stdout," Date : 07/07/2025 -  Ver. 2.1    \n\n");
    fprintf(stdout,"Utilizzo: lnid-hosts <comando>\n");
    fprintf(stdout,"Comandi:\n");
    fprintf(stdout,"  list      : mostra entries LNID in /etc/hosts\n");
    fprintf(stdout,"  clean     : rimuove tutte le entries LNID\n");
    fprintf(stdout,"  backup    : crea backup di /etc/hosts\n");
    fprintf(stdout,"  restore   : ripristina backup\n");
    fprintf(stdout,"  status    : mostra stato resolver daemon\n");
    return;
}

int show_lnid_entries() {
    FILE *hosts = fopen(HOSTS_FILE, "r");
    if (!hosts) {
        fprintf(stderr, "Errore apertura %s\n", HOSTS_FILE);
        return 0;
    }
    
    char line[1024];
    int in_lnid_section = 0;
    int count = 0;
    
    printf("=== Entries LNID in %s ===\n", HOSTS_FILE);
    
    while (fgets(line, sizeof(line), hosts)) {
        if (strstr(line, LNID_MARKER " START")) {
            in_lnid_section = 1;
            continue;
        }
        if (strstr(line, LNID_MARKER " END")) {
            in_lnid_section = 0;
            continue;
        }
        if (in_lnid_section && line[0] != '#' && line[0] != '\n') {
            printf("%s", line);
            count++;
        }
    }
    
    fclose(hosts);
    printf("\nTotale entries: %d\n", count);
    return 1;
}

int clean_lnid_entries() {
    if (geteuid() != 0) {
        fprintf(stderr, "Errore: privilegi root necessari\n");
        return 0;
    }
    
    FILE *src = fopen(HOSTS_FILE, "r");
    if (!src) {
        fprintf(stderr, "Errore apertura %s\n", HOSTS_FILE);
        return 0;
    }
    
    FILE *tmp = fopen("/tmp/hosts.clean", "w");
    if (!tmp) {
        fclose(src);
        fprintf(stderr, "Errore creazione file temporaneo\n");
        return 0;
    }
    
    char line[1024];
    int in_lnid_section = 0;
    int removed = 0;
    
    while (fgets(line, sizeof(line), src)) {
        if (strstr(line, LNID_MARKER " START")) {
            in_lnid_section = 1;
            continue;
        }
        if (strstr(line, LNID_MARKER " END")) {
            in_lnid_section = 0;
            continue;
        }
        if (!in_lnid_section) {
            fputs(line, tmp);
        } else if (line[0] != '#' && line[0] != '\n') {
            removed++;
        }
    }
    
    fclose(src);
    fclose(tmp);
    
    if (rename("/tmp/hosts.clean", HOSTS_FILE) == 0) {
        printf("Rimosse %d entries LNID da %s\n", removed, HOSTS_FILE);
        return 1;
    } else {
        fprintf(stderr, "Errore aggiornamento %s\n", HOSTS_FILE);
        return 0;
    }
}

int backup_hosts() {
    if (geteuid() != 0) {
        fprintf(stderr, "Errore: privilegi root necessari\n");
        return 0;
    }
    
    char backup_name[256];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(backup_name, sizeof(backup_name), "/etc/hosts.backup.%Y%m%d_%H%M%S", tm_info);
    
    FILE *src = fopen(HOSTS_FILE, "r");
    if (!src) {
        fprintf(stderr, "Errore apertura %s\n", HOSTS_FILE);
        return 0;
    }
    
    FILE *dst = fopen(backup_name, "w");
    if (!dst) {
        fclose(src);
        fprintf(stderr, "Errore creazione backup %s\n", backup_name);
        return 0;
    }
    
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), src)) {
        fputs(buffer, dst);
    }
    
    fclose(src);
    fclose(dst);
    
    printf("Backup creato: %s\n", backup_name);
    return 1;
}

int show_resolver_status() {
    printf("=== Stato LNID Resolver ===\n");
    system("systemctl is-active lnid-resolver >/dev/null 2>&1 && echo 'Servizio: ATTIVO' || echo 'Servizio: INATTIVO'");
    system("systemctl is-enabled lnid-resolver >/dev/null 2>&1 && echo 'Avvio automatico: ABILITATO' || echo 'Avvio automatico: DISABILITATO'");
    
    printf("\nUltime entries scoperte:\n");
    show_lnid_entries();
    
    printf("\nComandi utili:\n");
    printf("  sudo systemctl start lnid-resolver    # Avvia\n");
    printf("  sudo systemctl stop lnid-resolver     # Ferma\n");
    printf("  sudo systemctl status lnid-resolver   # Stato dettagliato\n");
    printf("  sudo journalctl -u lnid-resolver -f   # Log in tempo reale\n");
    
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_usage();
        return EXIT_FAILURE;
    }
    
    if (strcmp(argv[1], "list") == 0) {
        return show_lnid_entries() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcmp(argv[1], "clean") == 0) {
        return clean_lnid_entries() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcmp(argv[1], "backup") == 0) {
        return backup_hosts() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcmp(argv[1], "status") == 0) {
        return show_resolver_status() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else {
        fprintf(stderr, "Comando non riconosciuto: %s\n", argv[1]);
        print_usage();
        return EXIT_FAILURE;
    }
}