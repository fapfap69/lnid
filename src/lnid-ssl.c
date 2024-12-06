/* ----------------------------------------------------------
    LNID - Local Network Identity Discovery

   Libreria funzioni supporto SSL

 Copyright (c) 2024 Antonio Franco

 Questo programma è rilasciato sotto la licenza Creative Commons Attribuzione 4.0 Internazionale (CC BY 4.0).
 Puoi condividere, copiare, distribuire e modificare il programma, a condizione di dare il dovuto credito all'autore originale.

 Licenza completa: https://creativecommons.org/licenses/by/4.0/
 
 auth. A.Franco - INFN Bary Italy
 date: 28/11/2024       ver.1.1

 ---------------------------------------------------------
  HISTORY 
  28/11/2024  -  Creation
  06/12/2024  -  Versione 2.0 - OK

 ---------------------------------------------------------
*/
#ifndef __SSLSUPPORT__
#define __SSLSUPPORT__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>

#define PRIVKEYFILES "/tmp/privateserkey.pem"
#define PUBKEYFILES "/tmp/publicserkey.pem"
#define PRIVKEYFILEC "/tmp/privateclikey.pem"
#define PUBKEYFILEC "/tmp/publicclikey.pem"
#define SERVERPUBKEY "/tmp/serverpubkey.pem"
#define CLIENTPUBKEY "/tmp/clientpubkey.pem"

#define KEY_SIZE 2048
#define EXPONENT RSA_F4
#define PADDING RSA_PKCS1_OAEP_PADDING
// -----------

#define FALSE 0
#define TRUE 1

// Variabili globali
extern int isVerbose; // definito nel main program 
static const char *propq = NULL;

// stampa l'errore e abort del programma
//
void errorAndExit(const char* msg) 
{
    fprintf(stderr, "OSSL Errore : %s\n", msg);
    char buf[256];
    int err = ERR_get_error();
    ERR_error_string_n(err, buf, sizeof(buf));
    fprintf(stderr, "num err = %d, %s\n", err, buf);
    exit(EXIT_FAILURE);
}

// ---- Genera la coppia di chiavi Priv e Pub ----
// Ret: la coppia di chiavi generate, NULL per errore
//
EVP_PKEY *generateRsaKeyPair(unsigned int bits) 
{
    const uint32_t exponent = 0x10001;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(ctx == NULL) {
        errorAndExit("generateRsaKeyPair() : Non posso creare il contesto per RSA_PSS"); 
    }
    if(EVP_PKEY_keygen_init(ctx) <= 0) {
        errorAndExit("generateRsaKeyPair() : Inizializzazione del contesto RSA non riuscito");
    }
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        errorAndExit("generateRsaKeyPair() : Set per la chiave RSA non riuscito");
    }
    BIGNUM* exponent_bn = BN_new();
    BN_set_word(exponent_bn, exponent);
    if(EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, exponent_bn) <= 0) {
        errorAndExit("generateRsaKeyPair() : EVP_PKEY_CTX_set_rsa_keygen_pubexp fallito !");
    }
    EVP_PKEY* pkey = NULL;
    if(EVP_PKEY_keygen(ctx, &pkey) != 1) { 
        errorAndExit("generateRsaKeyPair() : Generazione della coppia di chiavi non riuscita !");
    }
    EVP_PKEY_CTX_free(ctx);
    return(pkey);
}

// ---- Stampa il contenuto della chiave ----
//
void dumpKeyPair(EVP_PKEY *keypair) {
    printf("----- Coppia di chiavi : Pubblica -----\n");
    EVP_PKEY_print_public_fp(stdout, keypair, 1, NULL);
    printf("----- Coppia di chiavi : Privata  -----\n");
    EVP_PKEY_print_private_fp(stdout, keypair, 1, NULL); 
    printf("----------------~ O ^ O ~--------------\n");
    return;
}

// --- crea due file PEM a partire da una struttura EVP_PKEY
//  Ret = FALSE per errore
//
int storeRSAKeyPair(EVP_PKEY *keypair, const char *publicKeyPEM, const char *privateKeyPEM) {
    FILE *fp = NULL;  
    fp = fopen(publicKeyPEM, "w");
    if(fp == NULL) { 
        fprintf(stderr, "storeRsaKeyPair() : Errore creazione file PEM chiave pubblica = %s",publicKeyPEM);
        return FALSE;
    }
    if (PEM_write_PUBKEY(fp, keypair) == 0) {
        fprintf(stderr, "storeRsaKeyPair() : Errore di scrittura PEM-encoded della chiave pubblica\n");
        fclose(fp);
        return FALSE;
    }
    fclose(fp);

    fp = fopen(privateKeyPEM, "w"); // Output a PEM encoding of the private key. 
    if(fp == NULL) { 
        fprintf(stderr, "storeRsaKeyPair() : Errore creazione file PEM chiave privata = %s",privateKeyPEM); 
        return FALSE;
    }
    if (PEM_write_PrivateKey(fp, keypair, NULL, NULL, 0, NULL, NULL) == 0) {
        fprintf(stderr, "storeRsaKeyPair() : Errore di scrittura PEM-encoded della chiave privata\n");
        fclose(fp);
        return FALSE;
    }
    fclose(fp);
    return(TRUE);
}

// ---- Carica la chiave da un file PEM
// Ret = la chiave letta, NULL per errore
//
EVP_PKEY *loadKeyFromPEM(OSSL_LIB_CTX *libctx, const char *fileName, const char *passphrase)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    int selection = 0; // Auto selection 

    FILE *fp = NULL;
    fp = fopen(fileName, "rb");
    if(fp == NULL) { 
        fprintf(stderr, "loadKeyFromPEM() : Errore lettura file PEM : %s\n", fileName);
        goto cleanup;
    }
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, "RSA", selection, libctx, propq);
    if (dctx == NULL) {
        fprintf(stderr, "loadKeyFromPEM() : errore OSSL_DECODER_CTX_new_for_pkey() !\n");
        goto cleanup;
    }
    if (passphrase != NULL) {
        if (OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char *)passphrase, strlen(passphrase)) == 0) {
            fprintf(stderr, "loadKeyFromPEM() : errore OSSL_DECODER_CTX_set_passphrase() !\n");
            goto cleanup;
        }
    }
    if (OSSL_DECODER_from_fp(dctx, fp) == 0) { 
        fprintf(stderr, "loadKeyFromPEM() : errore OSSL_DECODER_from_fp() !\n");
        goto cleanup;
    }
    ret = 1;
cleanup:
    if(dctx != NULL) OSSL_DECODER_CTX_free(dctx);
    if(fp != NULL) fclose(fp);
    if (ret == 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return pkey;
}

// ---- Regista la chiave in un file PEM -------
// La selection controlla se la private key e' esportata EVP_PKEY_KEYPAIR
// o solo la pubblica EVP_PKEY_PUBLIC_KEY
// Ret = FALSE per errore
//
int storeKeyInPEM(EVP_PKEY *pkey, const char *fileName, int selection, const char *passphrase)
{
    int ret = FALSE;
    OSSL_ENCODER_CTX *ectx = NULL;

    FILE *fp = NULL;
    fp = fopen(fileName, "w");
    if(fp == NULL) { 
        fprintf(stderr, "storeKeyInPEM() : Errore creazione del file PEM : %s\n", fileName);
        goto cleanup;
    }
    // Crea un PEM encoder ctx.
    // selection = (passphrase != NULL) ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", NULL, propq);
    if (ectx == NULL) {
        fprintf(stderr, "storeKeyInPEM() : OSSL_ENCODER_CTX_new_for_pkey() errore!\n");
        goto cleanup;
    }
    // setta la passward 
    if (passphrase != NULL) {
        if (OSSL_ENCODER_CTX_set_cipher(ectx, "AES-128-CBC", propq) == 0) {
            fprintf(stderr, "storeKeyInPEM() : OSSL_ENCODER_CTX_set_cipher() failed\n");
            goto cleanup;
        }
        if (OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char *)passphrase, strlen(passphrase)) == 0) {
            fprintf(stderr, "storeKeyInPEM() : OSSL_ENCODER_CTX_set_passphrase() failed\n");
            goto cleanup;
        }
    }
    if (OSSL_ENCODER_to_fp(ectx, fp) == 0) { // Codifica e scrittura nel file 
        fprintf(stderr, "storeKeyInPEM() : OSSL_ENCODER_to_fp() failed\n");
        goto cleanup;
    }
    ret = TRUE;
cleanup:
    fclose(fp);
    OSSL_ENCODER_CTX_free(ectx);
    return ret;
}

// ---- Regista la chiave in un buffer di memoria -------
// La selection controlla se la private key e' esportata EVP_PKEY_KEYPAIR
// o solo la pubblica EVP_PKEY_PUBLIC_KEY
// Ret = FALSE per errore
//
int storeKeyInMem(EVP_PKEY *pkey, char **memBuffer, size_t *bufLen, int selection)
{
    int ret = FALSE;
    OSSL_ENCODER_CTX *ectx = NULL;

    // Crea un PEM encoder ctx.
    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", NULL, propq);
    if (ectx == NULL) {
        fprintf(stderr, "storeKeyInMem() : OSSL_ENCODER_CTX_new_for_pkey() errore!\n");
        goto cleanup;
    }
    *memBuffer = NULL; // resetta per fare allocare 
    if(OSSL_ENCODER_to_data(ectx, (unsigned char **)memBuffer, bufLen) == FALSE) {
        fprintf(stderr, "storeKeyInMem() : errore di OSSL_ENCODER_to_data() !\n");
        goto cleanup;
    }
    ret = TRUE;
cleanup:
    OSSL_ENCODER_CTX_free(ectx);
    return ret;
}

// Esegue la decriptatura con chiave privata
// Ritorna TRUE / FALSE
//
static int doDecrypt(EVP_PKEY *privateKey, const unsigned char *in, size_t in_len,
                      unsigned char **out, size_t *out_len)
{
    EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if(EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
        errorAndExit("doDecrypt() : EVP_PKEY_encrypt_init errore !");
    }
    if(EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        errorAndExit("doDecrypt() : EVP_PKEY_CTX_set_rsa_padding errore !");
    }
    // calcola la dimensione
    if(EVP_PKEY_decrypt(dec_ctx, NULL, out_len, in, in_len) <= 0) {
        errorAndExit("doDecrypt() : EVP_PKEY_decrypt dry errore !");
    }
    // alloca il buffer
    size_t buf_len = *out_len;
    unsigned char *buf = NULL;
    buf = OPENSSL_malloc(buf_len + 2);
    if(buf == NULL) {
        errorAndExit("doDecrypt() : Errore di allocazione OPENSSL_malloc().\n");
    }
    // Decifra
    if(EVP_PKEY_decrypt(dec_ctx, buf, &buf_len, in, in_len) <= 0) {
        errorAndExit("doDecrypt() : EVP_PKEY_decrypt errore !");
    }
    *out_len = buf_len;
    *out = buf;
    if(isVerbose) {
        fprintf(stdout, "Decifrati %zu bytes:\n",buf_len);
        BIO_dump_indent_fp(stdout, buf, buf_len, 2);
        fprintf(stdout, "\n");
    }
    EVP_PKEY_CTX_free(dec_ctx);
    return(TRUE);
}

// Esegue la criptatura con chiave pubblica
// Return TRUE/FALSE
//
static int doEncrypt(EVP_PKEY *publicKey, const unsigned char *in, size_t in_len,
                     unsigned char **out, size_t *out_len)
{
    // Crea un nuovo contesto per criptare.
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
        errorAndExit("doEncrypt() : EVP_PKEY_encrypt_init errore !");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        errorAndExit("doEncrypt() : EVP_PKEY_CTX_set_rsa_padding errore !");
    }
    // Determina la dimensione dell'output
    if (EVP_PKEY_encrypt(enc_ctx, NULL, out_len, in, in_len) <= 0) {
        errorAndExit("doEncrypt() : dry EVP_PKEY_encrypt errore !");
    }
    // alloca il buffer
    size_t buf_len = *out_len;
    unsigned char *buf = NULL;
    buf = OPENSSL_malloc(buf_len + 2);
    if(buf == NULL) {
        errorAndExit("doEncrypt() : Errore di allocazione OPENSSL_malloc().\n");
    }
    // Cifratura
    if(EVP_PKEY_encrypt(enc_ctx, buf, &buf_len, in, in_len) <= 0) {
        errorAndExit("doEncrypt() : EVP_PKEY_encrypt errore !");
    }
    *out_len = buf_len;
    *out = buf;
    if(isVerbose) {
        fprintf(stdout, "Cifrati %zu bytes :\n",buf_len);
        BIO_dump_indent_fp(stdout, buf, buf_len, 2);
        fprintf(stdout, "\n");
    }
    EVP_PKEY_CTX_free(enc_ctx);
    return(TRUE);
}

// ---- Libera la memoria allocata per le chiavi RSA
//
void freeRsaKeyPair(EVP_PKEY *keypair) {
    EVP_PKEY_free(keypair);   
    return;
}

#endif
// --------  EOF ---------
