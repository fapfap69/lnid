/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Header per lnidd.c - Server daemon

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#ifndef __LNIDD_H__
#define __LNIDD_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/evp.h>
#include "lnid-common.h"

// Dichiarazioni funzioni
void print_usage(void);
void decode_cmdline(int argc, char *argv[]);
void signal_handler(int sig);
void load_config_file(void);
void check_hostname_at_startup(void);
int isAuthorizedIP(uint32_t ip_addr);
void buildTheResponse(char *message, uint32_t client_ip);
void handleClientMessage(void *client, char *message, size_t *bytes_received);
int checkRateLimit(uint32_t ip_addr);
void cleanupRateLimitTable(void);

#endif // __LNIDD_H__