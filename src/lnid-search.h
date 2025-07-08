/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Header per lnid-search.c - Search

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#ifndef __LNID_SEARCH_H__
#define __LNID_SEARCH_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "lnid-common.h"

// Dichiarazioni funzioni
void print_usage(void);
void decode_cmdline(int argc, char *argv[]);
void scan_subnet(const char *subnet, const char *mask, EVP_PKEY *pairKey);

#endif // __LNID_SEARCH_H__