/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 */
#include <string.h>
#include <stdlib.h>
#include <sdkey.h>

/* all algirithm ids are coming from GM/T 0006-2012 */
alg_t gm_ciphers[] = {
    {"SM1_ECB", SGD_SM1_ECB, 0},
    {"SM1_CBC", SGD_SM1_CBC, 0},
    {"SM1_CFB", SGD_SM1_CFB, 0},
    {"SM1_OFB", SGD_SM1_OFB, 0},
    {"SM1_MAC", SGD_SM1_MAC, 0},
    {"SSF33_ECB", SGD_SSF33_ECB, 0},
    {"SSF33_CBC", SGD_SSF33_CBC, 0},
    {"SSF33_CFB", SGD_SSF33_CFB, 0},
    {"SSF33_OFB", SGD_SSF33_OFB, 0},
    {"SSF33_MAC", SGD_SSF33_MAC, 0},
    {"SM4_ECB", SGD_SM4_ECB, 0},
    {"SM4_CBC", SGD_SM4_CBC, 0},
    {"SM4_CFB", SGD_SM4_CFB, 0},
    {"SM4_OFB", SGD_SM4_OFB, 0},
    {"SM4_MAC", SGD_SM4_MAC, 0},
    {NULL, 0, 0}
};

alg_t gm_pubs[] = {
    {"RSA", SGD_RSA, 0},
    {"SM2_ecdsa", SGD_SM2_1, 0},
    {"SM2_ecdh", SGD_SM2_2, 0},
    {"SM2_ecies", SGD_SM2_3, 0},
    {NULL, 0, 0}
};

alg_t gm_dgsts[] = {
    {"SM3", SGD_SM3, 0},
    {"SHA1", SGD_SHA1, 0},
    {"SHA256", SGD_SHA256, 0},
    {NULL, 0, 0}
};

// return boolean
int algIsSupported(ULONG algId)
{
    alg_t *alg;

    for (alg = gm_ciphers; alg->name; alg++) {
        if (algId == alg->id && alg->supported) {
            return 1;
        }
    }

    for (alg = gm_pubs; alg->name; alg++) {
        if (algId == alg->id && alg->supported) {
            return 1;
        }
    }

    for (alg = gm_dgsts; alg->name; alg++) {
        if (algId == alg->id && alg->supported) {
            return 1;
        }
    }

    return 0;
}

static void ShowDeviceInfo(DEVINFO *info)
{
    alg_t *palg;

    DEBUG_MSG("================================\n");
    DEBUG_MSG("device info:\n");
    DEBUG_MSG("Versin: %d.%d\n", info->Version.major, info->Version.minor);
    DEBUG_MSG("Vendor: %s\n", info->Manufacturer);
    DEBUG_MSG("Issuer: %s\n", info->Issuer);
    DEBUG_MSG("Label: %s\n", info->Label);
    DEBUG_MSG("Serial: %s\n", info->SerialNumber);
    DEBUG_MSG("HWVersion: %d.%d\n", info->HWVersion.major, info->HWVersion.minor);
    DEBUG_MSG("FirmWare: %d.%d\n", info->FirmwareVersion.major, 
            info->FirmwareVersion.minor);
    DEBUG_MSG("DevAuthAlgId: 0x%08x\n", info->DevAuthAlgId);
    DEBUG_MSG("TotalSpace: 0x%08x\n", info->TotalSpace);
    DEBUG_MSG("FreeSpace: 0x%08x\n", info->FreeSpace);
    DEBUG_MSG("================================\n");
    DEBUG_MSG("cipher algorithm: \n");
    for (palg = gm_ciphers; palg->name; palg++) {
        if ((palg->id & info->AlgSymCap) == palg->id) {
            palg->supported = 1;
            DEBUG_MSG("\t[%s] is supported\n", palg->name);
        } else {
            DEBUG_MSG("\t[%s] is UNSUPPORTED\n", palg->name);
            palg->supported = 0;
        }
    }
    DEBUG_MSG("================================\n");
    DEBUG_MSG("public key algorithm: \n");
    for (palg = gm_pubs; palg->name; palg++) {
        if ((palg->id & info->AlgAsymCap) == palg->id) {
            palg->supported = 1;
            DEBUG_MSG("\t[%s] is supported\n", palg->name);
        } else {
            DEBUG_MSG("\t[%s] is UNSUPPORTED\n", palg->name);
            palg->supported = 0;
        }
    }
    DEBUG_MSG("================================\n");
    DEBUG_MSG("hash algorithm: \n");
    for (palg = gm_dgsts; palg->name; palg++) {
        if ((palg->id & info->AlgHashCap) == palg->id) {
            palg->supported = 1;
            DEBUG_MSG("\t[%s] is supported\n", palg->name);
        } else {
            DEBUG_MSG("\t[%s] is UNSUPPORTED\n", palg->name);
            palg->supported = 0;
        }
    }
    DEBUG_MSG("================================\n");
}

int dev_manage_test(sdkey_data_t *data)
{
    ULONG rv, listLen;
    CHAR devList[512], buf[128];
    DEVINFO info = {0};
    char input[128];
    int ret = 0, num;

    listLen = sizeof (buf) / sizeof (CHAR);
    rv = SKF_EnumDev(TRUE, devList, &listLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EnumDev ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    num = NameListShow(devList, listLen);
    if (num < 1) {
        ERROR_MSG("There is no device avaliable.\n");
        goto error;
    }

    if (!GetInput("Input the dev name:", input, sizeof (input))) {
        ERROR_MSG("Get the dev name ERROR.\n");
        goto error;
    }

    rv = SKF_ConnectDev(input, &data->hDev);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ConnectDev ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    DEBUG_MSG("open device[%s] ok\n", input);

    memset(buf, 0, sizeof (buf));
    memcpy(buf, LABEL_NAME, strlen(LABEL_NAME));
    rv = SKF_SetLabel(data->hDev, buf);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_SetLabel ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    DEBUG_MSG("set device label to[%s] ok \n", LABEL_NAME);

    rv = SKF_GetDevInfo(data->hDev, &info);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GetDevInfo ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    ShowDeviceInfo(&info);

    data->DevAuthAlgId = info.DevAuthAlgId;

    rv = SKF_LockDev(data->hDev, 1000);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_LockDev ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_UnlockDev(data->hDev);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_UnlockDev ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    DEBUG_MSG("device[%s] lock/unlock ok\n", input);

    ret = 1;
error:
    return ret;
}
