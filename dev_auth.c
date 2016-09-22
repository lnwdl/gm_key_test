/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 */
#include <string.h>
#include <stdlib.h>
#include <sdkey.h>

int dev_auth_test(sdkey_data_t *data)
{
    ULONG rv, rndLen, outLen, authLen, listLen, retry_cnt;
    BYTE rnd[16] = {0}, out[32] = {0};
    BYTE authKey[] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
                      0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
    CHAR appList[256];
    HANDLE hKey = NULL;
    BLOCKCIPHERPARAM param;
    int ret = 0, num;

    // gen 8 byte random, padding the left to 0 */
    rv = SKF_GenRandom(data->hDev, rnd, RND_LEN);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenRandom ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_SetSymmKey(data->hDev, authKey, data->DevAuthAlgId, &hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_SetSymmKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    memset(&param, 0x0, sizeof (param));
    rv = SKF_EncryptInit(hKey, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rndLen = sizeof (rnd) / sizeof (BYTE);
    outLen = sizeof (out) / sizeof (BYTE);

    rv = SKF_Encrypt(hKey, rnd, rndLen, out, &outLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_Encrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_CloseHandle(hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseHandle ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // auth
    rv = SKF_DevAuth(data->hDev, out, outLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_DevAuth ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    authLen = sizeof (authKey) / sizeof (BYTE);
    rv = SKF_ChangeDevAuthKey(data->hDev, authKey, authLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ChangeDevAuthKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    SKF_DeleteApplication(data->hDev, APP_NAME);
    rv = SKF_CreateApplication(data->hDev, APP_NAME, ADM_PIN, RETRY_NUM,
            USR_PIN, RETRY_NUM, SECURE_ANYONE_ACCOUNT, &data->hApp);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CreateApplication ERROR, errno[0x%08x]\n", rv);
        data->hApp = NULL;
        goto error;
    }
    DEBUG_MSG("create application[%s] ok\n", APP_NAME);

    retry_cnt = 1;
    while (retry_cnt) {
        rv = SKF_VerifyPIN(data->hApp, USER_TYPE, USR_PIN, &retry_cnt);
        if (rv != SAR_OK) {
            ERROR_MSG("SKF_CreateApplication ERROR, errno[0x%08x]\n", rv);
            DEBUG_MSG("Retry counter is: [%ld]\n", retry_cnt);
            continue;
        }

        break;
    }
    if (rv != SAR_OK) {
        ERROR_MSG("verify pin code ERROR\n");
        goto error;
    }
    DEBUG_MSG("verify application[%s] pin ok\n", APP_NAME);

    rv = SKF_ClearSecureState(data->hApp);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ClearSecureState ERROR, errno[0x%08x]\n", rv);
        data->hApp = NULL;
        goto error;
    }
    DEBUG_MSG("clear application[%s] secure state ok\n", APP_NAME);

    rv = SKF_CreateContainer(data->hApp, CON1_NAME, &data->hCon1);
    if (rv != 0x0A00002D) { // user not log in
        ERROR_MSG("SKF_CreateContainer ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    rv = SKF_CreateContainer(data->hApp, CON1_NAME, &data->hCon2);
    if (rv != 0x0A00002D) { // user not log in
        ERROR_MSG("SKF_CreateContainer ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    data->hCon1 = NULL;
    data->hCon2 = NULL;

    rv = SKF_CloseApplication(data->hApp);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseApplication ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    data->hApp = NULL;
    DEBUG_MSG("close application[%s] ok\n", APP_NAME);

    listLen = sizeof (appList) / sizeof (CHAR);
    rv = SKF_EnumApplication(data->hDev, appList, &listLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EnumApplication ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    if (!NameListFind(appList, listLen, APP_NAME)) {
        ERROR_MSG("Find app name[%s] ERROR\n", APP_NAME);
        goto error;
    }

    rv = SKF_OpenApplication(data->hDev, APP_NAME, &data->hApp);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_OpenApplication ERROR, errno[0x%08x]\n", rv);
        data->hApp = NULL;
        goto error;
    }
    DEBUG_MSG("open application[%s] ok\n", APP_NAME);

    retry_cnt = 1;
    while (retry_cnt) {
        rv = SKF_VerifyPIN(data->hApp, USER_TYPE, USR_PIN, &retry_cnt);
        if (rv != SAR_OK) {
            ERROR_MSG("SKF_CreateApplication ERROR, errno[0x%08x]\n", rv);
            DEBUG_MSG("Retry counter is: [%ld]\n", retry_cnt);
            continue;
        }

        break;
    }
    if (rv != SAR_OK) {
        ERROR_MSG("verify pin code ERROR\n");
        goto error;
    }
    DEBUG_MSG("verify application[%s] pin ok\n", APP_NAME);

    ret = 1;
error:
    return ret;
}

