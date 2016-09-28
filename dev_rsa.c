/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 */
#include <string.h>
#include <stdlib.h>
#ifdef USE_CRYPTO
#include <openssl/rsa.h>
#endif
#include <sdkey.h>

#define CON_NAME    "con_rsa"

static int padding_PKCS1_type2(unsigned char *to, const size_t tlen, 
        const unsigned char *from, const size_t flen)
{
    size_t i, j;
    unsigned char *p;

    if (flen > tlen - 11) {
        return 0;   /* data too large for key size */
    }

    p = to;

    *(p++) = 0;
    *(p++) = 2;     /* Public Key Block Type */

    /* pad left data with no-zero random data */
    j = tlen - 3 - flen;
    for (i = 0; i < j; i++) {
        do {
            *p = rand() & 0xff;
        } while (*p == '\0');
        p++;
    }

    *(p++) = '\0';
    memcpy(p, from, flen);

    return 1;
}

static int generateSignKeyPair(HCONTAINER hCon, ULONG BitsLen)
{
    RSAPUBLICKEYBLOB sign_pub;
    ULONG rv;
    int ret;

    rv = SKF_GenRSAKeyPair(hCon, BitsLen, &sign_pub);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenRSAKeyPair ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
    return ret;
}

static int importEncKeyPair(DEVHANDLE hDev, HCONTAINER hCon)
{
    ULONG rv, keyLen, padLen, encLen, cipLen, len, algId;
    RSAPUBLICKEYBLOB sign_pub;
    BLOCKCIPHERPARAM param;
    HANDLE hKey = NULL;
    BYTE key[16] = {0};
    BYTE enc[4096], cip[4096];
#ifdef USE_CRYPTO
    BIGNUM *bn = NULL;
    RSA *rsa = NULL;
    unsigned char *der = NULL;
    int dlen;
#else
    RSAPRIVATEKEYBLOB enc_pri;
#endif
    char *pad = NULL;
    int ret = 0;

    // export sign public key
    len = sizeof (sign_pub);
    rv = SKF_ExportPublicKey(hCon, 1, (BYTE *)&sign_pub, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportPublicKey sign ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // generate random cipher key
    keyLen = sizeof (key) / sizeof (BYTE);
    rv = SKF_GenRandom(hDev, key, keyLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenRandom ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // padding the cipher key to byteLen 
    padLen = sign_pub.BitLen / 8;
    pad = malloc(padLen * sizeof (char));
    if (!pad) {
        ERROR_MSG("malloc keyPad ERROR\n");
        goto error;
    }
    if (padding_PKCS1_type2(pad, padLen, key, keyLen) <= 0) {
        ERROR_MSG("padding_PKCS1_type2 ERROR\n");
        goto error;
    }

    // use signer's sign public key to encrypt the cipher key
    encLen = sizeof (enc) / sizeof (BYTE);
    rv = SKF_ExtRSAPubKeyOperation(hDev, &sign_pub, pad, padLen,
            enc, &encLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExtRSAPubKeyOperation ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /************************************************/
    //generate a random rsa private key
#ifdef USE_CRYPTO
    bn = BN_new();
    if (!bn) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }
    if (!BN_set_word(bn, RSA_F4)) {
        ERROR_MSG("BN_set_word ERROR\n");
        goto error;
    }
    rsa = RSA_new();
    if (!rsa) {
        ERROR_MSG("RSA_new ERROR\n");
        goto error;
    }
    if (!RSA_generate_key_ex(rsa, sign_pub.BitLen, bn, NULL)) {
        ERROR_MSG("RSA_generate_key_ex ERROR\n");
        goto error;
    }
    dlen = i2d_RSAPrivateKey(rsa, &der);
    if (dlen <= 0) {
        ERROR_MSG("i2d_RSAPrivateKey ERROR\n");
        goto error;
    }
#else
    rv = SKF_GenExtRSAKey(hDev, sign_pub.BitLen, &enc_pri);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenExtRSAKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /* TODO: der encode the enc_pri */
#error "You need to der encode the enc_pri"
#endif

    // use cipher key to encrypt the private key to cipher text */
    algId = SGD_SM1_ECB;
    rv = SKF_SetSymmKey(hDev, key, algId, &hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenRandom ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    param.IVLen = 0;
    param.PaddingType = 1;  // PKCS#5
    rv = SKF_EncryptInit(hKey, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    cipLen = sizeof (cip) / sizeof (BYTE);
#ifdef USE_CRYPTO
    rv = SKF_Encrypt(hKey, der, dlen, cip, &cipLen);
#else
    rv = SKF_Encrypt(hKey, (BYTE *)&enc_pri, sizeof (enc_pri),
            cip, &cipLen);
#endif
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_Encrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /************************************************/
    //import enc key
    rv = SKF_ImportRSAKeyPair(hCon, algId, enc, encLen, cip, cipLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ImportRSAKeyPair ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
#ifdef USE_CRYPTO
    if (bn) BN_free(bn);
    if (rsa) RSA_free(rsa);
    if (der) OPENSSL_free(der);
#endif
    if (pad) free(pad);
    if (hKey) SKF_CloseHandle(hKey);

    return ret;
}

static int rsaSignVerify(DEVHANDLE hDev, HCONTAINER hCon)
{
    RSAPUBLICKEYBLOB sign_pub;
    BYTE in[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    BYTE sig[1024];
    ULONG rv, inLen, sigLen, len;
    int ret = 0;

    // export sign public key
    len = sizeof (sign_pub);
    rv = SKF_ExportPublicKey(hCon, 1, (BYTE *)&sign_pub, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportPublicKey sign ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    inLen = sizeof (in) / sizeof (BYTE);
    sigLen = sizeof (sig) /sizeof (BYTE);
    rv = SKF_RSASignData(hCon, in, inLen, sig, &sigLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_RSASignData ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_RSAVerify(hDev, &sign_pub, in, inLen, sig, sigLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_RSAVerify ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
    return ret;
}

static int rsaEncDec(DEVHANDLE hDev, ULONG bitsLen)
{
    ULONG rv, inLen, padLen, encLen, decLen;
    RSAPRIVATEKEYBLOB enc_pri;
    RSAPUBLICKEYBLOB enc_pub;
    BYTE in[] = {
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
    };
    BYTE enc[4096], dec[4096];
    BYTE *pad = NULL;
    int ret = 0;
    
    // generate a random enc key pair 
    rv = SKF_GenExtRSAKey(hDev, bitsLen, &enc_pri);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenExtRSAKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    enc_pub.AlgID = enc_pri.AlgID;
    enc_pub.BitLen = enc_pri.BitLen;
    memcpy(enc_pub.Modulus, enc_pri.Modulus, sizeof (enc_pri.Modulus));
    memcpy(enc_pub.PublicExponent, 
            enc_pri.PublicExponent, sizeof (enc_pri.PublicExponent));

    // pad the plain text to (bitsLen / 8)
    inLen = sizeof (in) / sizeof (BYTE);
    padLen = (bitsLen / 8) * sizeof (BYTE);
    pad = malloc(padLen);
    if (!pad) {
        ERROR_MSG("malloc pad ERROR\n");
        goto error;
    }
    if (!padding_PKCS1_type2(pad, padLen, in, inLen)) {
        ERROR_MSG("padding_PKCS1_type2 ERROR\n");
        goto error;
    }

    // encrypt
    encLen = sizeof (enc) / sizeof (BYTE);
    rv = SKF_ExtRSAPubKeyOperation(hDev, &enc_pub, pad, padLen, enc, &encLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExtRSAPubKeyOperation ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // decrypt
    decLen = sizeof (dec) / sizeof (BYTE);
    rv = SKF_ExtRSAPriKeyOperation(hDev, &enc_pri, enc, encLen, dec, &decLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExtRSAPriKeyOperation ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    if (decLen != padLen || memcmp(dec, pad, decLen)) {
        ERROR_MSG("rsa enc/dec ERROR\n");
        DEBUG_MSG("plain_text:\n");
        ShwHexBuf(pad, padLen);
        DEBUG_MSG("enc text:\n");
        ShwHexBuf(enc, encLen);
        DEBUG_MSG("dec text:\n");
        ShwHexBuf(dec, decLen);
        goto error;
    }

    ret = 1;
error:
    if (pad) free(pad);

    return ret;
}

static int rsaSessionCipher(DEVHANDLE hDev, HCONTAINER hCon1, HCONTAINER hCon2)
{
    ULONG rv, len, skLen, algId;
    RSAPUBLICKEYBLOB enc_pub2;
    BYTE sesKey[256];
    HANDLE hKey1 = NULL, hKey2 = NULL;
    BLOCKCIPHERPARAM param;
    BYTE plain_txt[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
    BYTE enc_txt[256], dec_txt[256];
    ULONG plain_len, enc_len, dec_len;
    int ret = 0;

    /* export con2's enc public key */
    len = sizeof (enc_pub2);
    rv = SKF_ExportPublicKey(hCon2, 0, (BYTE *)&enc_pub2, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportPublicKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /* export/import session key */
    algId = SGD_SM1_ECB;
    skLen = sizeof (sesKey) / sizeof (BYTE);
    rv = SKF_RSAExportSessionKey(hCon1, algId, &enc_pub2, sesKey, &skLen, &hKey1);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_RSAExportSessionKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_ImportSessionKey(hCon2, algId, sesKey, skLen, &hKey2);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ImportSessionKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /* use hKey1 to encrypt */
    plain_len = sizeof (plain_txt) / sizeof (BYTE);
    enc_len = sizeof (enc_txt) / sizeof (BYTE);
    dec_len = sizeof (dec_txt) / sizeof (BYTE);

    param.IVLen = 0;
    param.PaddingType = 1;

    rv = SKF_EncryptInit(hKey1, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    rv = SKF_Encrypt(hKey1, plain_txt, plain_len, enc_txt, &enc_len);
    if (rv != SAR_OK) {
        ERROR_MSG("hKey1 SKF_Encrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_DecryptInit(hKey2, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    rv = SKF_Decrypt(hKey2, enc_txt, enc_len, dec_txt, &dec_len);
    if (rv != SAR_OK) {
        ERROR_MSG("hKey2 SKF_Decrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    if ((dec_len != plain_len) || memcmp(dec_txt, plain_txt, dec_len)) {
        ERROR_MSG("rsa plain text and dec text is different\n");
        DEBUG_MSG("plain_txt:\n");
        ShwHexBuf(plain_txt, plain_len);
        DEBUG_MSG("enc_txt:\n");
        ShwHexBuf(enc_txt, enc_len);
        DEBUG_MSG("dec_txt:\n");
        ShwHexBuf(dec_txt, dec_len);

        goto error;
    }

    ret = 1;
error:
    if (hKey1) SKF_CloseHandle(hKey1);
    if (hKey2) SKF_CloseHandle(hKey2);

    return ret;
}

static int rsa_test(sdkey_data_t *data, ULONG bitsLen)
{
    ULONG rv, conType;
    int ret = -1;

    SKF_DeleteContainer(data->hApp, CON1_NAME);
    SKF_DeleteContainer(data->hApp, CON2_NAME);
    rv = SKF_CreateContainer(data->hApp, CON1_NAME, &data->hCon1);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CreateContainer ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    rv = SKF_CreateContainer(data->hApp, CON2_NAME, &data->hCon2);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_CreateContainer ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // generate rsa sign key pair
    if (!generateSignKeyPair(data->hCon1, bitsLen)) {
        ERROR_MSG("generateSignKeyPair ERROR\n");
        goto error;
    }
    if (!generateSignKeyPair(data->hCon2, bitsLen)) {
        ERROR_MSG("generateSignKeyPair ERROR\n");
        goto error;
    }
    DEBUG_MSG("rsa[%ld] generate rsa sign key pair ok\n", bitsLen);

    // import rsa enc key pair
    if (!importEncKeyPair(data->hDev, data->hCon1)) {
        ERROR_MSG("importEncKeyPair ERROR\n");
        goto error;
    }
    if (!importEncKeyPair(data->hDev, data->hCon2)) {
        ERROR_MSG("importEncKeyPair ERROR\n");
        goto error;
    }
    DEBUG_MSG("rsa[%ld] import encrypt key pair ok\n", bitsLen);

    rv = SKF_GetContainerType(data->hCon1, &conType);
    if (rv != SAR_OK || conType != 1) {
        ERROR_MSG("SKF_GetContainerType ERROR, errno[0x%08x], type[0x%08x]\n", 
                rv, conType);
        goto error;
    }
    DEBUG_MSG("rsa[%ld] get container typte ok\n", bitsLen);

    /* test sign/verify */
    if (!rsaSignVerify(data->hDev, data->hCon1)) {
        ERROR_MSG("rsa[%ld] sign/verify ERROR\n", bitsLen);
    } else {
        DEBUG_MSG("rsa[%ld] sign/verify ok\n", bitsLen);
    }

    /* test enc/dec */
    if (!rsaEncDec(data->hDev, bitsLen)) {
        ERROR_MSG("rsa[%ld] encrypt/decrypt ERROR\n", bitsLen);
    } else {
        DEBUG_MSG("rsa[%ld] encrypt/decrypt ok\n", bitsLen);
    }

    /* test export/import session key and cipher enc/dec */
    if (!rsaSessionCipher(data->hDev, data->hCon1, data->hCon2)) {
        ERROR_MSG("rsa[%ld] export/import session ERROR\n", bitsLen);
        goto error;
    } else {
        DEBUG_MSG("rsa[%ld] export/import session ok\n", bitsLen);
    }

    ret = 0;
error:
    if (data->hCon1) {
        SKF_CloseContainer(data->hCon1);
        data->hCon1 = NULL;
    }
    if (data->hCon2) {
        SKF_CloseContainer(data->hCon2);
        data->hCon2 = NULL;
    }

    return ret;
}

int dev_rsa_test(sdkey_data_t *data)
{
    if (!algIsSupported(SGD_RSA)) {
        DEBUG_MSG("rsa algorithm is UNSUPPORTED\n");
        return 0;
    }

    rsa_test(data, 1024);
    rsa_test(data, 2048);

    return 1;
}
