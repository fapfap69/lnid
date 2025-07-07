/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Tool gestione server LNID

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void print_usage() {
    fprintf(stdout,"***  LNID Server Manager  ***\n");
    fprintf(stdout," Auth: A.Franco - INFN Bari Italy \n");
    fprintf(stdout," Date : 07/07/2025 -  Ver. 2.1    \n\n");
    fprintf(stdout,"Utilizzo: lnid-server <comando>\n");
    fprintf(stdout,"Comandi:\n");
    fprintf(stdout,"  status    : mostra stato server daemon\n");
    fprintf(stdout,"  config    : mostra configurazione attuale\n");
    fprintf(stdout,"  test      : testa connessione al server locale\n");
    fprintf(stdout,"  start     : avvia il servizio\n");
    fprintf(stdout,"  stop      : ferma il servizio\n");
    fprintf(stdout,"  restart   : riavvia il servizio\n");
    return;
}

int show_server_status() {
    printf("=== Stato LNID Server ===\n");
    system("systemctl is-active lnid >/dev/null 2>&1 && echo 'Servizio: ATTIVO' || echo 'Servizio: INATTIVO'");
    system("systemctl is-enabled lnid >/dev/null 2>&1 && echo 'Avvio automatico: ABILITATO' || echo 'Avvio automatico: DISABILITATO'");
    
    printf("\nDettagli servizio:\n");
    system("systemctl status lnid --no-pager -l");
    
    printf("\nComandi utili:\n");
    printf("  sudo systemctl start lnid      # Avvia\n");
    printf("  sudo systemctl stop lnid       # Ferma\n");
    printf("  sudo systemctl restart lnid    # Riavvia\n");
    printf("  sudo journalctl -u lnid -f     # Log in tempo reale\n");
    
    return 1;
}

int show_config() {
    printf("=== Configurazione LNID Server ===\n");
    
    FILE *config = fopen("/etc/lnid-server.conf", "r");
    if (!config) {
        printf("File configurazione non trovato: /etc/lnid-server.conf\n");
        return 0;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), config)) {
        if (line[0] != '#' && line[0] != '\n') {
            printf("  %s", line);
        }
    }
    fclose(config);
    
    printf("\nPer modificare: sudo nano /etc/lnid-server.conf\n");
    printf("Dopo le modifiche: sudo systemctl restart lnid\n");
    
    return 1;
}

int test_server() {
    printf("=== Test Server LNID Locale ===\n");
    
    // Legge configurazione per ottenere porta
    FILE *config = fopen("/etc/lnid-server.conf", "r");
    int port = 16969; // default
    
    if (config) {
        char line[256];
        while (fgets(line, sizeof(line), config)) {
            if (strncmp(line, "PORT=", 5) == 0) {
                port = atoi(line + 5);
                break;
            }
        }
        fclose(config);
    }
    
    printf("Testando server su localhost:%d...\n", port);
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "lnid-cli -i 127.0.0.1 -p %d 2>/dev/null", port);
    
    int result = system(cmd);
    if (result == 0) {
        printf("✓ Server LNID risponde correttamente\n");
    } else {
        printf("✗ Server LNID non risponde\n");
        printf("Verifica che il servizio sia attivo: lnid-server status\n");
    }
    
    return result == 0;
}

int control_service(const char *action) {
    if (geteuid() != 0) {
        fprintf(stderr, "Errore: privilegi root necessari per %s il servizio\n", action);
        return 0;
    }
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "systemctl %s lnid", action);
    
    printf("Eseguendo: %s...\n", cmd);
    int result = system(cmd);
    
    if (result == 0) {
        printf("✓ Comando eseguito con successo\n");
        // Mostra stato dopo l'azione
        system("systemctl status lnid --no-pager -l");
    } else {
        printf("✗ Errore nell'esecuzione del comando\n");
    }
    
    return result == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_usage();
        return EXIT_FAILURE;
    }
    
    if (strcmp(argv[1], "status") == 0) {
        return show_server_status() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcmp(argv[1], "config") == 0) {
        return show_config() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcmp(argv[1], "test") == 0) {
        return test_server() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcmp(argv[1], "start") == 0) {
        return control_service("start") ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcmp(argv[1], "stop") == 0) {
        return control_service("stop") ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcmp(argv[1], "restart") == 0) {
        return control_service("restart") ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else {
        fprintf(stderr, "Comando non riconosciuto: %s\n", argv[1]);
        print_usage();
        return EXIT_FAILURE;
    }
}