/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 */
#include <string.h>
#include <stdlib.h>
#include <sdkey.h>

static int generateSignKeyPair(HCONTAINER hCon)
{
    ECCPUBLICKEYBLOB sign_pub;
    ULONG rv;
    int ret;

    rv = SKF_GenECCKeyPair(hCon, SGD_SM2_1, &sign_pub);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenECCKeyPair ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
    return ret;
}

/* 
 * there is no SKF_GenExtECCKey now in the specific GM/T 0016-2012 
 * we can use SKF_GenerateAgreementDataWithECC instead.
 */
static BYTE bEccPrikey[] = {       
  0xB1,0xE7,0xFD,0xCB,0x32,0x12,0x1C,0x67,0x3A,0xB7,0x99,0xE5,0xED,0x7B,0xD7,0x86,
  0x60,0xA3,0xA1,0x54,0x30,0x55,0xDB,0x4A,0x0D,0x94,0xD0,0xEF,0xB6,0x98,0x56,0x73
};
static BYTE bEccPubkey[] = {   
  0xF0,0x80,0x36,0x1D,0x43,0xE6,0x5B,0x47,0xE8,0xF0,0xD2,0xC1,0x5E,0x99,0x98,0x5E,
  0xD7,0x86,0xED,0x29,0x30,0x8D,0xFF,0xAB,0xB5,0xF0,0x43,0x21,0x6A,0xD6,0x87,0xC2,
  0x50,0x73,0x3E,0x09,0xE0,0x1A,0x48,0xF3,0xBA,0xA5,0xCD,0x7E,0x90,0x35,0xFD,0x76,
  0x6C,0xEB,0x7B,0xFD,0x4D,0x23,0x48,0xA2,0x66,0x94,0x2D,0xBC,0x10,0xE4,0x84,0x56
};

static int importEncKeyPair(DEVHANDLE hDev, HCONTAINER hCon)
{
    ULONG rv, len, keyLen, encLen, cipLen, algId, envLen;
    ECCPUBLICKEYBLOB sign_pub;
    ECCPRIVATEKEYBLOB enc_pri;
    ECCCIPHERBLOB *enc = NULL;
    ENVELOPEDKEYBLOB *env = NULL;
    BLOCKCIPHERPARAM param;
    HANDLE hKey = NULL;
    BYTE key[16] = {0}, cip[4096];
    int ret = 0;

    // export sign public key
    len = sizeof (sign_pub);
    rv = SKF_ExportPublicKey(hCon, 1, (BYTE *)&sign_pub, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportPublicKey sign ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // generate random cipher key
    keyLen = sizeof (key) / sizeof(BYTE);
    rv = SKF_GenRandom(hDev, key, keyLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenRandom ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // use signer's public key to enc the key
    encLen = sizeof (ECCCIPHERBLOB) + keyLen;
    enc = malloc(encLen);
    if (!enc) {
        ERROR_MSG("malloc ERROR\n");
        goto error;
    }
    rv = SKF_ExtECCEncrypt(hDev, &sign_pub, key, keyLen, enc);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExtECCEncrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /******************************************/
    //generate a ecc private key
    memset(&enc_pri, 0, sizeof (enc_pri));
    enc_pri.BitLen = sign_pub.BitLen;
    memcpy(enc_pri.PrivateKey + sizeof(enc_pri.PrivateKey) - sizeof(bEccPrikey), 
            bEccPrikey, sizeof (bEccPrikey));   /* align to right */

    // use key to encrypt the private key to cipher text */
    algId = SGD_SM1_ECB;
    rv = SKF_SetSymmKey(hDev, key, algId, &hKey);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenRandom ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    param.IVLen = 0;
    param.PaddingType = 0;

    rv = SKF_EncryptInit(hKey, param);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_EncryptInit ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // encrpyt the (enc_pri.PrivateKey) other then the (enc_pri)
    cipLen = sizeof (cip) / sizeof (BYTE);
    rv = SKF_Encrypt(hKey, enc_pri.PrivateKey, sizeof (enc_pri.PrivateKey),
            cip, &cipLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_Encrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /******************************************/
    // compse ENVELOPEDKEYBLOB
    envLen = sizeof (ENVELOPEDKEYBLOB) + keyLen;
    env = malloc(envLen);
    if (!env) {
        ERROR_MSG("malloc ERROR\n");
        goto error;
    }
    env->Version = 1;
    env->ulSymmAlgID = algId;
    env->ulBits = sign_pub.BitLen;
    memcpy(env->cbEncryptedPriKey, cip, cipLen);

    env->PubKey.BitLen = env->ulBits;
    memcpy(env->PubKey.XCoordinate + 
                sizeof (env->PubKey.XCoordinate) - 
                sizeof (bEccPrikey), 
            bEccPubkey, sizeof (bEccPrikey));
    memcpy(env->PubKey.YCoordinate +
                sizeof (env->PubKey.YCoordinate) - 
                sizeof (bEccPrikey), 
            bEccPubkey + sizeof (bEccPrikey), sizeof (bEccPrikey));

    memcpy(&(env->ECCCipherBlob), enc, encLen);

    /******************************************/
    //import enc key
    rv = SKF_ImportECCKeyPair(hCon, env);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ImportECCKeyPair ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
    if (enc) free(enc);
    if (env) free(env);
    if (hKey) SKF_CloseHandle(hKey);

    return ret;
}

static int eccSignVerify(DEVHANDLE hDev, HCONTAINER hCon)
{
    ECCPUBLICKEYBLOB sign_pub;
    ECCSIGNATUREBLOB sig;
    BYTE in[32] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    ULONG rv, inLen, len;
    int ret = 0;

    if (!algIsSupported(SGD_SM2_1)) {
        DEBUG_MSG("ecc ecdsa algorithm is UNSUPPORTED\n");
        goto error;
    }

    // export sign public key
    len = sizeof (sign_pub);
    rv = SKF_ExportPublicKey(hCon, 1, (BYTE *)&sign_pub, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportPublicKey sign ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    inLen = sizeof (in) / sizeof (BYTE);
    rv = SKF_ECCSignData(hCon, in, inLen, &sig);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_RSASignData ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_ECCVerify(hDev, &sign_pub, in, inLen, &sig);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_RSAVerify ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
    return ret;
}

static int eccEncDec(DEVHANDLE hDev)
{
    ULONG rv, inLen, cipLen, decLen;
    ECCPUBLICKEYBLOB enc_pub;
    ECCPRIVATEKEYBLOB enc_pri;
    ECCCIPHERBLOB *cip = NULL;
    BYTE in[] = {
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
    };
    BYTE dec[1024];
    int ret = 0;

    if (!algIsSupported(SGD_SM2_3)) {
        DEBUG_MSG("ecc ecies algorithm is UNSUPPORTED\n");
        goto error;
    }

    inLen = sizeof (in) / sizeof (BYTE);

    // generate a random enc key pair
    enc_pub.BitLen = 256;
    memcpy(enc_pub.XCoordinate + sizeof (enc_pub.XCoordinate) - 32,
            bEccPubkey, 32);
    memcpy(enc_pub.YCoordinate + sizeof (enc_pub.YCoordinate) - 32,
            bEccPubkey + 32, 32);
    enc_pri.BitLen = 256;
    memcpy(enc_pri.PrivateKey + sizeof (enc_pri.PrivateKey) - sizeof (bEccPrikey),
            bEccPrikey, sizeof (bEccPrikey));

    cip = malloc(sizeof (ECCCIPHERBLOB) + inLen);
    if (!cip) {
        ERROR_MSG("malloc cip ERROR\n");
        goto error;
    }

    rv = SKF_ExtECCEncrypt(hDev, &enc_pub, in, inLen, cip);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExtECCEncrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    decLen = sizeof (dec) / sizeof (BYTE);
    rv = SKF_ExtECCDecrypt(hDev, &enc_pri, cip, dec, &decLen);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExtECCDecrypt ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    if (decLen != inLen || memcmp(in, dec, inLen)) {
        ERROR_MSG("ecc plain text && dec text compare ERROR\n");
        DEBUG_MSG("plain text:\n");
        ShwHexBuf(in, inLen);
        DEBUG_MSG("dec text:\n");
        ShwHexBuf(dec, decLen);
        goto error;
    }

    ret = 1;
error:
    if (cip) free(cip);

    return ret;
}

static int eccSessionCipher(DEVHANDLE hDev, HCONTAINER hCon1, HCONTAINER hCon2)
{
    ULONG rv, len, skLen, algId;
    ECCPUBLICKEYBLOB enc_pub2;
    ECCCIPHERBLOB *sesKey = NULL;
    HANDLE hKey1 = NULL, hKey2 = NULL;
    BLOCKCIPHERPARAM param;
    BYTE plain_txt[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
    BYTE enc_txt[256], dec_txt[256];
    ULONG plain_len, enc_len, dec_len;
    int ret = 0;

    if (!algIsSupported(SGD_SM2_3)) {
        DEBUG_MSG("ecc ecies algorithm is UNSUPPORTED\n");
        goto error;
    }

    /* export con2's enc public key */
    len = sizeof (enc_pub2);
    rv = SKF_ExportPublicKey(hCon2, 0, (BYTE *)&enc_pub2, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportPublicKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    // how long the skLen ?
    skLen = sizeof (ECCCIPHERBLOB) * 2;
    sesKey = malloc(skLen);
    if (!sesKey) {
        ERROR_MSG("mallo ERROR\n");
        goto error;
    }

    algId = SGD_SM1_ECB;
    rv = SKF_ECCExportSessionKey(hCon1, algId, &enc_pub2, sesKey, &hKey1);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_RSAExportSessionKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_ImportSessionKey(hCon2, algId, 
            (BYTE *)sesKey, sizeof (ECCCIPHERBLOB) + sesKey->CipherLen, 
            &hKey2);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ImportSessionKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /* use hKey1 encrypt */
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
        ERROR_MSG("plain text and dec text is different\n");
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
    if (sesKey) free(sesKey);

    return ret;
}

static int eccAgreement(DEVHANDLE hDev, HCONTAINER hCon1, HCONTAINER hCon2)
{
    ULONG rv, len, algId;
    ECCPUBLICKEYBLOB enc_pub1;
    ECCPUBLICKEYBLOB enc_pub2;
    ECCPUBLICKEYBLOB tmp_pub1;
    ECCPUBLICKEYBLOB tmp_pub2;
    BLOCKCIPHERPARAM param;
    HANDLE hAgr = NULL, hKey1 = NULL, hKey2 = NULL;
    BYTE plain_txt[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
    BYTE enc_txt[256], dec_txt[256];
    ULONG plain_len, enc_len, dec_len;
    int ret = 0;

    if (!algIsSupported(SGD_SM2_2)) {
        DEBUG_MSG("ecc ecdh algorithm is UNSUPPORTED\n");
        goto error;
    }

    /* export enc public key of con1 and con2 */
    len = sizeof (enc_pub1);
    rv = SKF_ExportPublicKey(hCon1, 0, (BYTE *)&enc_pub1, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportPublicKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    len = sizeof (enc_pub2);
    rv = SKF_ExportPublicKey(hCon2, 0, (BYTE *)&enc_pub2, &len);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_ExportPublicKey ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /* generate tmp public key of con1 and con2 */
    algId = SGD_SM1_ECB;
    /* 1) sponsor 1 */
    rv = SKF_GenerateAgreementDataWithECC(hCon1, algId,
            &tmp_pub1,
            CON1_NAME, strlen(CON1_NAME),
            &hAgr);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenerateAgreementDataWithECC ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /* 2) responsor */
    rv = SKF_GenerateAgreementDataAndKeyWithECC(hCon2, algId,
            &enc_pub1,
            &tmp_pub1,
            &tmp_pub2,
            CON2_NAME, strlen(CON2_NAME),
            CON1_NAME, strlen(CON1_NAME),
            &hKey2);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenerateAgreementDataAndKeyWithECC ERROR, errno[0x%08x]\n", 
                rv);
        goto error;
    }

    /* 3) sponsor 2 */
    rv = SKF_GenerateKeyWithECC(hAgr,
            &enc_pub2,
            &tmp_pub2,
            CON2_NAME, strlen(CON2_NAME),
            &hKey1);
    if (rv != SAR_OK) {
        ERROR_MSG("SKF_GenerateKeyWithECC ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    /* use hKey1 encrypt */
    plain_len = sizeof (plain_txt) / sizeof (BYTE);
    enc_len = sizeof (enc_txt) / sizeof (BYTE);
    dec_len = sizeof (dec_txt) / sizeof (BYTE);

    param.IVLen = 0;
    param.PaddingType = 0;

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
        ERROR_MSG("plain text and dec text is different\n");
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
    if (hAgr) SKF_CloseHandle(hAgr);
    if (hKey1) SKF_CloseHandle(hKey1);
    if (hKey2) SKF_CloseHandle(hKey2);

    return ret;
}

int dev_ecc_test(sdkey_data_t *data)
{
    ULONG rv, conType, inLen;
    ECCPUBLICKEYBLOB pubKey;
    BYTE in[32] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    int ret = 0;

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

    // generate ecc sign key pair
    if (!generateSignKeyPair(data->hCon1)) {
        ERROR_MSG("generateSignKeyPair ERROR\n");
        goto error;
    }
    if (!generateSignKeyPair(data->hCon2)) {
        ERROR_MSG("generateSignKeyPair ERROR\n");
        goto error;
    }
    DEBUG_MSG("ecc generate ecdsa key pair ok\n");

    // import ecc enc key pair
    if (!importEncKeyPair(data->hDev, data->hCon1)) {
        ERROR_MSG("importEncKeyPair ERROR\n");
        goto error;
    }
    if (!importEncKeyPair(data->hDev, data->hCon2)) {
        ERROR_MSG("importEncKeyPair ERROR\n");
        goto error;
    }
    DEBUG_MSG("ecc import ecies key pair ok\n");

    rv = SKF_GetContainerType(data->hCon1, &conType);
    if (rv != SAR_OK || conType != 2) {
        ERROR_MSG("SKF_GetContainerType ERROR, errno[0x%08x], type[0x%08x]\n", 
                rv, conType);
        goto error;
    }
    DEBUG_MSG("ecc get container type ok\n");

    /* test sign/verify */
    if (!eccSignVerify(data->hDev, data->hCon1)) {
        ERROR_MSG("ecc sign/verify ERROR\n");
    } else {
        DEBUG_MSG("ecc sign/verify ok\n");
    }

    /* test encrypt/decrypt */
    if (!eccEncDec(data->hDev)) {
        ERROR_MSG("ecc encrypt/decrypt ERROR\n");
    } else {
        DEBUG_MSG("ecc encrypt/decrypt ok\n");
    }

    /* test export/import session */
    if (!eccSessionCipher(data->hDev, data->hCon1, data->hCon2)) {
        ERROR_MSG("ecc export/import session ERROR\n");
    } else {
        DEBUG_MSG("ecc export/import session ok\n");
    }

    if (!eccAgreement(data->hDev, data->hCon1, data->hCon2)) {
        ERROR_MSG("ecc agrement ERROR\n");
        goto error;
    } else {
        DEBUG_MSG("ecc agrement ok\n");
    }

    ret = 1;
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
