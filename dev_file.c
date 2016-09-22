/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 */
#include <string.h>
#include <stdlib.h>
#include <sdkey.h>

#define FILE_NAME   "file_test"
#define FILE_OFFSET 0x10

int dev_file_test(sdkey_data_t *data)
{
    ULONG rv, fileLen, listLen, wLen, rLen, bLen;
    CHAR fileList[256];
    BYTE wdata[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    BYTE rdata[256];
    FILEATTRIBUTE info;
    int ret = 0, num;

    fileLen = 0x100;
    rv = SKF_CreateFile(data->hApp, FILE_NAME, fileLen, 
            SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CreateFile ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    DEBUG_MSG("create file[%s] ok\n", FILE_NAME);

    listLen = sizeof (fileList) / sizeof (CHAR);
    rv = SKF_EnumFiles(data->hApp, fileList, &listLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EnumFiles ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    if (!NameListFind(fileList, listLen, FILE_NAME)) {
        ERROR_MSG("Find file name[%s] ERROR\n", FILE_NAME);
        goto error;
    }

    memset(&info, 0, sizeof (info));
    rv = SKF_GetFileInfo(data->hApp, FILE_NAME, &info);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GetFileInfo ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    DEBUG_MSG("stat file[%s] ok\n", FILE_NAME);
    DEBUG_MSG("file[%s] name: %s\n", FILE_NAME, info.FileName);
    DEBUG_MSG("file[%s] size: %ld\n", FILE_NAME, info.FileSize);

    wLen = sizeof (wdata) / sizeof (BYTE);
    rv = SKF_WriteFile(data->hApp, FILE_NAME, FILE_OFFSET, wdata, wLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_WriteFile ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rLen = bLen = sizeof (rdata) / sizeof (BYTE);
    memset(rdata, 0, bLen);
    rv = SKF_ReadFile(data->hApp, FILE_NAME, FILE_OFFSET, bLen, rdata, &rLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ReadFile ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    if (wLen != rLen) {
        ERROR_MSG("read len(%ld) != write len(%ld) ERROR\n", rLen, wLen);
        goto error;
    }

    if (memcmp(wdata, rdata, wLen) != 0) {
        ERROR_MSG("read/write data compare ERROR\n");
        DEBUG_MSG("Write data is:\n");
        ShwHexBuf(wdata, wLen);
        DEBUG_MSG("Read data is:\n");
        ShwHexBuf(rdata, rLen);
        goto error;
    }

    ret = 1;
error:
    rv = SKF_DeleteFile(data->hApp, FILE_NAME);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_DeleteFile ERROR, errno[0x%08x]\n", rv);
    }
    DEBUG_MSG("delete file[%s] ok\n", FILE_NAME);

    return ret;
}
