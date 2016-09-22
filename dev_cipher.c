/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 */
#include <string.h>
#include <stdlib.h>
#include <sdkey.h>

static int cipher_one_test(sdkey_data_t *data, const char *name, ULONG hwId)
{
    ULONG rv, inLen, encLen, decLen;
    HANDLE hKey = NULL;
    BLOCKCIPHERPARAM param;
    BYTE in[] = {
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
    };
    BYTE key[] = {
        0x37,0xB7,0xE3,0x25,0x9C,0x36,0xE3,0x8E,
        0xC3,0xA5,0x85,0x86,0x10,0xb5,0xb0,0x7a
    };
    BYTE enc[4096], dec[4096];
    int ret = 0;

    // The length must be the multiple of block length, else error.
    inLen = sizeof (in) / sizeof (BYTE);

    param.PaddingType = 0;
    param.IVLen = 16;
    memset(param.IV, 0x00, 16);
    param.FeedBitLen = 0;

    // enc
    rv = SKF_SetSymmKey(data->hDev, key, hwId, &hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_SetSymmKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_EncryptInit(hKey, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    encLen = sizeof (enc) / sizeof (BYTE);
    rv = SKF_Encrypt(hKey, in, inLen, enc, &encLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_Encrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_CloseHandle(hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseHandle ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    hKey = NULL;

    // dec
    rv = SKF_SetSymmKey(data->hDev, key, hwId, &hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_SetSymmKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_DecryptInit(hKey, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    decLen = sizeof (dec) / sizeof (BYTE);
    rv = SKF_Decrypt(hKey, enc, encLen, dec, &decLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_Decrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_CloseHandle(hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseHandle ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    hKey = NULL;

    if (inLen != decLen || memcmp(in, dec, inLen) != 0) {
        ERROR_MSG("cipher[%s] one time ERROR\n", name);
        DEBUG_MSG("plain data is:\n");
        ShwHexBuf(in, inLen);
        DEBUG_MSG("decrypt data is:\n");
        ShwHexBuf(dec, decLen);
        goto error;
    }

    DEBUG_MSG("cipher[%s] one time ok\n", name);

    ret = 1;
error:
    if (hKey) SKF_CloseHandle(hKey);

    return ret;
}

static int cipher_three_test(sdkey_data_t *data, const char *name, ULONG hwId)
{
    ULONG rv, inLen, encLen, decLen, left;
    HANDLE hKey;
    BLOCKCIPHERPARAM param;
    BYTE in[] = {
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
    };
    BYTE key[] = {
        0x37,0xB7,0xE3,0x25,0x9C,0x36,0xE3,0x8E,
        0xC3,0xA5,0x85,0x86,0x10,0xb5,0xb0,0x7a
    };
    BYTE enc[4096], dec[4096], *penc;
    int ret = 0, i;

    inLen = sizeof (in) / sizeof (BYTE);

    param.PaddingType = 0;
    param.IVLen = 16;
    memset(param.IV, 0x00, 16);
    param.FeedBitLen = 0;

    // enc
    rv = SKF_SetSymmKey(data->hDev, key, hwId, &hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_SetSymmKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_EncryptInit(hKey, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    encLen = sizeof (enc) / sizeof (BYTE);
    penc = enc;
    left = encLen;
    for (i = 0; i < 3; ++i) {
        rv = SKF_EncryptUpdate(hKey, in, inLen, penc, &left);
        if (rv != SAR_OK) {
            ERROR_MSG("SKF_EncryptUpdate ERROR, errno[0x%08x]\n", rv);
            goto error;
        }

        penc += left;
        encLen -= left;
        left = encLen;
    }
    rv = SKF_EncryptFinal(hKey, penc, &left);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptFinal ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    penc += left;
    encLen = penc - enc;

    rv = SKF_CloseHandle(hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseHandle ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // dec
    rv = SKF_SetSymmKey(data->hDev, key, hwId, &hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_SetSymmKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_DecryptInit(hKey, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_DecryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    decLen = sizeof (dec) / sizeof (BYTE);
    rv = SKF_Decrypt(hKey, enc, encLen, dec, &decLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_Decrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_CloseHandle(hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseHandle ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    hKey = NULL;

    if ((inLen * 3) != decLen || memcmp(in, dec, inLen) != 0) {
        ERROR_MSG("cipher[%s] three time enc/dec ERROR\n", name);
        DEBUG_MSG("plain data len: %ld\n", decLen);
        ShwHexBuf(in, inLen);
        DEBUG_MSG("decrypt data len: %ld\n", decLen);
        ShwHexBuf(dec, decLen);
        goto error;
    }
    DEBUG_MSG("cipher[%s] three time enc/dec ok\n", name);

    ret = 1;
error:
    if (hKey) SKF_CloseHandle(hKey);

    return ret;
}

static void cipher_test(sdkey_data_t *data, const char *name, ULONG hwId)
{
    if (!algIsSupported(hwId)) {
        DEBUG_MSG("cipher algorithm[%s] is UNSUPPORTED\n", name);
        return;
    }

    cipher_one_test(data, name, hwId);
    cipher_three_test(data, name, hwId);
}

int dev_cipher_test(sdkey_data_t *data)
{
    cipher_test(data, "SM1_ECB", SGD_SM1_ECB);
    cipher_test(data, "SM1_CBC", SGD_SM1_CBC);
    cipher_test(data, "SM1_CFB", SGD_SM1_CFB);
    cipher_test(data, "SM1_OFB", SGD_SM1_OFB);
    cipher_test(data, "SM4_ECB", SGD_SM4_ECB);
    cipher_test(data, "SM4_CBC", SGD_SM4_CBC);
    cipher_test(data, "SM4_CFB", SGD_SM4_CFB);
    cipher_test(data, "SM4_OFB", SGD_SM4_OFB);
    cipher_test(data, "SSF33_ECB", SGD_SSF33_ECB);
    cipher_test(data, "SSF33_CBC", SGD_SSF33_CBC);
    cipher_test(data, "SSF33_CFB", SGD_SSF33_CFB);
    cipher_test(data, "SSF33_OFB", SGD_SSF33_OFB);

    return 1;
}
