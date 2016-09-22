/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 */
#include <string.h>
#include <stdlib.h>
#include <sdkey.h>

#define CON_NAME    "con_test"

int dev_con_test(sdkey_data_t *data)
{
    ULONG rv, listLen, inLen, outLen, conType;
    CHAR conList[256];
    HCONTAINER hCon;
    BYTE icert[2048], ocert[2048];
    int ret = 0, num;

    SKF_DeleteContainer(data->hApp, CON_NAME);
    rv = SKF_CreateContainer(data->hApp, CON_NAME, &hCon);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CreateContainer ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    DEBUG_MSG("create container[%s] ok\n", CON_NAME);

    rv = SKF_CloseContainer(hCon);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseContainer ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    hCon = NULL;
    DEBUG_MSG("close container[%s] ok\n", CON_NAME);

    listLen = sizeof (conList) / sizeof (CHAR);
    rv = SKF_EnumContainer(data->hApp, conList, &listLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EnumContainer ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    if (!NameListFind(conList, listLen, CON_NAME)) {
        ERROR_MSG("Find container name[%s] ERROR\n", CON_NAME);
        goto error;
    }
    DEBUG_MSG("find container[%s] ok\n", CON_NAME);

    rv = SKF_OpenContainer(data->hApp, CON_NAME, &hCon);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_OpenContainer ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    DEBUG_MSG("open container[%s] ok\n", CON_NAME);

    rv = SKF_GetContainerType(hCon, &conType);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GetContainerType ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    switch (conType) {
        case 0:
            DEBUG_MSG("container[%s] type[UNKNOWN] ok\n", CON_NAME);
            break;
        case 1:
            DEBUG_MSG("container[%s] type[RSA] error\n", CON_NAME);
            break;
        case 2:
            DEBUG_MSG("container[%s] type[ECC] error\n", CON_NAME);
            break;
        default:
            DEBUG_MSG("container[%s] type[%ld] error\n", CON_NAME, conType);
            break;
    }

    /* import/export sign cert */
    inLen = 1234;
    memset(icert, 0x02, inLen);
    rv = SKF_ImportCertificate(hCon, TRUE, icert, inLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ImportCertificate ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    outLen = sizeof (ocert) / sizeof (BYTE);
    rv = SKF_ExportCertificate(hCon, TRUE, ocert, &outLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportCertificate ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    if (inLen != outLen || memcmp(icert, ocert, inLen) != 0) {
        ERROR_MSG("container[%s] import/export certificate ERROR\n");
        goto error;
    }
    DEBUG_MSG("container[%s] import/export sign cert ok\n", CON_NAME);

    ret = 1;
error:
    if (hCon) SKF_CloseContainer(hCon);

    return ret;
}
