/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Header per lnid-resolver.c - Resolver daemon

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#ifndef __LNID_RESOLVER_H__
#define __LNID_RESOLVER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include "lnid-common.h"

// Dichiarazioni funzioni
void load_config_file(void);
void print_usage(void);
void signal_handler(int sig);
int backup_hosts_file(void);
int cleanup_hosts_file(void);
int update_hosts_file(void);
void make_unique_lnid_hostname(char *hostname, const char *original, const char *ip);
void update_cache_entry(const char *ip, const char *hostname);
void scan_single_subnet(const char *single_subnet, EVP_PKEY *pairKey, int *total_discoveries);
void scan_network(void);
void daemonize(void);
void decode_cmdline(int argc, char *argv[]);

#endif // __LNID_RESOLVER_H__