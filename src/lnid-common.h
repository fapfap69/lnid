/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Header comune per definizioni e funzioni condivise

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#ifndef __LNID_COMMON_H__
#define __LNID_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

// Costanti comuni
#define LNID_VERSION "2.1"
#define LNID_DATE "07/07/2025"
#define LNID_AUTHOR "A.Franco - INFN Bari Italy"

// Codici di uscita standard
#define LNID_SUCCESS 0
#define LNID_ERROR 1
#define LNID_INVALID_ARGS 2
#define LNID_NETWORK_ERROR 3
#define LNID_CONFIG_ERROR 4

// Limiti comuni
#define MAX_HOSTNAME_LEN 256
#define MAX_IP_LEN 16
#define MAX_PORT 65535
#define MIN_PORT 1
#define MAX_DELAY_MS 10000
#define MAX_TIMEOUT_MS 30000

// Funzioni di utilità comuni
void lnid_print_header(const char *program_name, const char *description);
int lnid_validate_port(int port);
int lnid_validate_ip(const char *ip);
int lnid_validate_delay(int delay_ms);
int lnid_validate_timeout(int timeout_ms);
void lnid_print_error(const char *message);
void lnid_print_verbose(const char *format, ...);
char* lnid_get_timestamp(void);

// Variabili globali comuni
extern int isVerbose;

#endif // __LNID_COMMON_H__