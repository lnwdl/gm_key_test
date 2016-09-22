/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * macro/struct/function declarations.
 */
#ifndef __SDKEY_H__
#define __SDKEY_H__

#include <stdio.h>
#include <skf.h>

#define ERROR_MSG(format, ...) \
    fprintf(stderr, "%s|%d|"format, __FILE__, __LINE__, ##__VA_ARGS__) 

#define DEBUG_MSG(format, ...) \
    fprintf(stdout, format, ##__VA_ARGS__) 

#define LABEL_NAME  "lnwdl"
#define RND_LEN     8
#define APP_NAME    "app_test"
#define ADM_PIN     "88888888"
#define USR_PIN     "11111111"
#define CON1_NAME   "send"
#define CON2_NAME   "recv"
#define RETRY_NUM   6

typedef struct alg_s {
    const char *name;
    unsigned int id;
    int supported;
} alg_t;

typedef struct sdkey_data_s {
    DEVHANDLE hDev;
    HAPPLICATION hApp;
    HCONTAINER hCon1;
    HCONTAINER hCon2;
    ULONG DevAuthAlgId;
} sdkey_data_t;

// util.c
void ShwHexBuf(const unsigned char *buf, const size_t len);

// return: boolean
int GetInput(const char *prompt, char *out, size_t outlen);

// return the number of name.
int NameListShow(const char *nl, const size_t len);

// if find, return the name; NULL: find error;
const char *NameListFind(const char *nl, const size_t len, const char *name);

// dev_manage.c
int algIsSupported(ULONG algId);
int dev_manage_test(sdkey_data_t *data);

// dev_auth.c
int dev_auth_test(sdkey_data_t *data);

// dev_file.c
int dev_file_test(sdkey_data_t *data);

// dev_con.c
int dev_con_test(sdkey_data_t *data);

// dev_dgst.c
int dev_dgst_test(sdkey_data_t *data);

// dev_cipher.c
int dev_cipher_test(sdkey_data_t *data);

// dev_rsa.c
int dev_rsa_test(sdkey_data_t *data);

// dev_ecc.c
int dev_ecc_test(sdkey_data_t *data);

#endif
