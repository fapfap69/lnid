/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Implementazione funzioni comuni

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#include "lnid-common.h"
#include <stdarg.h>
#include <sys/socket.h>

// Definizione variabile globale
int isVerbose = 0;

// Stampa intestazione standard per tutti i programmi
void lnid_print_header(const char *program_name, const char *description) {
    fprintf(stdout, "***  %s  ***\n", program_name);
    fprintf(stdout, " %s\n", description);
    fprintf(stdout, " Auth: %s\n", LNID_AUTHOR);
    fprintf(stdout, " Date: %s - Ver. %s\n\n", LNID_DATE, LNID_VERSION);
}

// Valida numero di porta
int lnid_validate_port(int port) {
    return (port >= MIN_PORT && port <= MAX_PORT) ? 1 : 0;
}

// Valida indirizzo IP
int lnid_validate_ip(const char *ip) {
    if (!ip) return 0;
    
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

// Valida delay in millisecondi
int lnid_validate_delay(int delay_ms) {
    return (delay_ms >= 0 && delay_ms <= MAX_DELAY_MS) ? 1 : 0;
}

// Valida timeout in millisecondi
int lnid_validate_timeout(int timeout_ms) {
    return (timeout_ms > 0 && timeout_ms <= MAX_TIMEOUT_MS) ? 1 : 0;
}

// Stampa messaggio di errore con formato standard
void lnid_print_error(const char *message) {
    fprintf(stderr, "LNID ERROR: %s\n", message);
}

// Stampa messaggio verbose se abilitato
void lnid_print_verbose(const char *format, ...) {
    if (!isVerbose) return;
    
    va_list args;
    va_start(args, format);
    fprintf(stdout, "LNID VERBOSE: ");
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    va_end(args);
}

// Ottiene timestamp corrente come stringa
char* lnid_get_timestamp(void) {
    static char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    return timestamp;
}