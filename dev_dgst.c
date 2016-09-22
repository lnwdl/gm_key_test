/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 */
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <sdkey.h>

static int dev_hash1(DEVHANDLE hDev, ULONG algID, 
        unsigned char *in, size_t inlen, 
        unsigned char *out, size_t *outlen)
{
    ULONG rv, len;
    HANDLE hash;
    int ret = 0;

    rv = SKF_DigestInit(hDev, algID, NULL, NULL, 0, &hash);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_DigestInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    len = *outlen;
    rv = SKF_Digest(hash, in, inlen, out, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_Digest ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    *outlen = len;

    rv = SKF_CloseHandle(hash);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseHandle ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
    return ret;
}

static int dev_hash3(DEVHANDLE hDev, ULONG algID, 
        unsigned char *in, size_t inlen, 
        unsigned char *out, size_t *outlen)
{
    ULONG rv, len;
    HANDLE hash;
    int ret = 0, i;

    rv = SKF_DigestInit(hDev, algID, NULL, NULL, 0, &hash);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_DigestInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    for (i = 0; i < 3; ++i) {
        rv = SKF_DigestUpdate(hash, in, inlen);
        if (rv != SAR_OK) {
            ERROR_MSG("SKF_DigestInit ERROR, errno[0x%08x]\n", rv);
            goto error;
        }
    }

    len = *outlen;
    rv = SKF_DigestFinal(hash, out, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_Digest ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    *outlen = len;

    rv = SKF_CloseHandle(hash);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CloseHandle ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
    return ret;
}

#ifdef USE_CRYPTO
static int soft_hash1(EVP_MD_CTX *ctx, 
        unsigned char *in, size_t inlen,
        unsigned char *out, size_t *outlen)
{
    int len;

    len = *outlen;
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal(ctx, out, &len);

    *outlen = len;

    return 1;
}

static int soft_hash3(EVP_MD_CTX *ctx, 
        const unsigned char *in, const size_t inlen,
        unsigned char *out, size_t *outlen)
{
    int i, len;

    for (i = 0; i < 3; ++i) {
        EVP_DigestUpdate(ctx, in, inlen);
    }
    EVP_DigestFinal(ctx, out, &len);

    *outlen = len;

    return 1;
}
#endif

#ifdef USE_CRYPTO
static int hash_one_test(sdkey_data_t *data, const char *name, 
        ULONG hwId, const EVP_MD *sfId)
#else
static int hash_one_test(sdkey_data_t *data, const char *name, 
        ULONG hwId)
#endif
{
    BYTE in[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    BYTE dev_out[128];
    size_t inLen, devLen;
#ifdef USE_CRYPTO
    EVP_MD_CTX ctx;
    BYTE soft_out[128];
    size_t softLen;
#endif
    int ret = 0;

    inLen = sizeof (in) / sizeof (BYTE);

    devLen = sizeof (dev_out) / sizeof (BYTE);
    if (!dev_hash1(data->hDev, hwId, in, inLen, dev_out, &devLen)) {
        ERROR_MSG("hash[%s] dev_hash1 ERROR\n", name);
        goto error;
    }

#ifdef USE_CRYPTO
    EVP_DigestInit(&ctx, sfId);
    softLen = sizeof (soft_out) / sizeof (BYTE);
    soft_hash1(&ctx, in, inLen, soft_out, &softLen);
    EVP_MD_CTX_cleanup(&ctx);

    if (devLen != softLen || memcmp(dev_out, soft_out, devLen) != 0) {
        ERROR_MSG("hash[%s] one time ERROR\n", name);
        DEBUG_MSG("hardware hash[%s]:\n", name);
        ShwHexBuf(dev_out, devLen);
        DEBUG_MSG("software hash[%s]:\n", name);
        ShwHexBuf(soft_out, softLen);
    }
#endif

    DEBUG_MSG("hash[%s] one time ok\n", name);

    ret = 1;
error:
    return ret;
}

#ifdef USE_CRYPTO
static int hash_three_test(sdkey_data_t *data, const char *name, 
        ULONG hwId, const EVP_MD *sfId)
#else
static int hash_three_test(sdkey_data_t *data, const char *name, 
        ULONG hwId)
#endif
{
    BYTE in[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    BYTE dev_out[128];
    size_t inLen, devLen;
#ifdef USE_CRYPTO
    EVP_MD_CTX ctx;
    BYTE soft_out[128];
    size_t softLen;
#endif
    int ret = 0;

    inLen = sizeof (in) / sizeof (BYTE);
    devLen = sizeof (dev_out) / sizeof (BYTE);
    if (!dev_hash3(data->hDev, hwId, in, inLen, dev_out, &devLen)) {
        ERROR_MSG("hash[%s] dev_hash3 ERROR\n", name);
        goto error;
    }

#ifdef USE_CRYPTO
    EVP_DigestInit(&ctx, sfId);
    softLen = sizeof (soft_out) / sizeof (BYTE);
    soft_hash3(&ctx, in, inLen, soft_out, &softLen);
    EVP_MD_CTX_cleanup(&ctx);

    if (devLen != softLen || memcmp(dev_out, soft_out, devLen) != 0) {
        ERROR_MSG("hash[%s] three time ERROR\n", name);
        DEBUG_MSG("hardware hash[%s]:\n", name);
        ShwHexBuf(dev_out, devLen);
        DEBUG_MSG("software hash[%s]:\n", name);
        ShwHexBuf(soft_out, softLen);
        goto error;
    }
#endif

    DEBUG_MSG("hash[%s] three time ok\n", name);

    ret = 1;
error:
    return ret;
}

#ifdef USE_CRYPTO
static void hash_test(sdkey_data_t *data, const char *name, 
        ULONG hwId, const EVP_MD *sfId)
#else
static void hash_test(sdkey_data_t *data, const char *name, 
        ULONG hwId)
#endif
{
    if (!algIsSupported(hwId)) {
        DEBUG_MSG("hash algorithm[%s] is UNSUPPORTED\n", name);
        return;
    }

#ifdef USE_CRYPTO
    hash_one_test(data, name, hwId, sfId);
    hash_three_test(data, name, hwId, sfId);
#else
    hash_one_test(data, name, hwId);
    hash_three_test(data, name, hwId);
#endif
}

int dev_dgst_test(sdkey_data_t *data)
{
#ifdef USE_CRYPTO
    hash_test(data, "SHA1", SGD_SHA1, EVP_sha1());
    hash_test(data, "SHA256", SGD_SHA256, EVP_sha256());
    //hash_test(data, "SM3", SGD_SM3, EVP_sm3());
#else 
    hash_test(data, "SHA1", SGD_SHA1);
    hash_test(data, "SHA256", SGD_SHA256);
    hash_test(data, "SM3", SGD_SM3);
#endif

    return 1;
}
