/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Header per lnid-cli.c - Client

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#ifndef __LNID_CLI_H__
#define __LNID_CLI_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lnid-common.h"

// Dichiarazioni funzioni
void print_usage(void);
void decode_cmdline(int argc, char *argv[]);

#endif // __LNID_CLI_H__