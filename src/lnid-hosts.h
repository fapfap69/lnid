/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Header per lnid-hosts.c - Hosts manager

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#ifndef __LNID_HOSTS_H__
#define __LNID_HOSTS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

// Dichiarazioni funzioni
void print_usage(void);
int show_lnid_entries(void);
int clean_lnid_entries(void);
int backup_hosts(void);
int show_resolver_status(void);

#endif // __LNID_HOSTS_H__