/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Header per lnid-server.c - Server manager

 Copyright (c) 2024 Antonio Franco
 auth. A.Franco - INFN Bary Italy
 date: 07/07/2025       ver.2.1
 ---------------------------------------------------------
*/
#ifndef __LNID_SERVER_H__
#define __LNID_SERVER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Dichiarazioni funzioni
void print_usage(void);
int show_server_status(void);
int show_config(void);
int test_server(void);
int control_service(const char *action);

#endif // __LNID_SERVER_H__