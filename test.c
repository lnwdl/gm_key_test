#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sdkey.h>

int main(int argc, char *argv[])
{
    sdkey_data_t data;
    int ret;

    memset(&data, 0, sizeof (data));

    ret = dev_manage_test(&data);
    if (!ret) {
        ERROR_MSG("dev_manage_test --------------> ERROR\n");
        goto error;
    } else {
        DEBUG_MSG("dev_manage_test --------------> OK\n");
    }

    ret = dev_auth_test(&data);
    if (!ret) {
        ERROR_MSG("dev_auth_test --------------> ERROR\n");
        goto error;
    } else {
        DEBUG_MSG("dev_auth_test --------------> OK\n");
    }

    ret = dev_file_test(&data);
    if (!ret) {
        ERROR_MSG("dev_file_test --------------> ERROR\n");
    } else {
        DEBUG_MSG("dev_file_test --------------> OK\n");
    }

    ret = dev_dgst_test(&data);
    if (!ret) {
        ERROR_MSG("dev_dgst_test --------------> ERROR\n");
    } else {
        DEBUG_MSG("dev_dgst_test --------------> OK\n");
    }

    ret = dev_cipher_test(&data);
    if (!ret) {
        ERROR_MSG("dev_cipher_test --------------> ERROR\n");
    } else {
        DEBUG_MSG("dev_cipher_test --------------> OK\n");
    }

    ret = dev_con_test(&data);
    if (!ret) {
        ERROR_MSG("dev_con_test --------------> ERROR\n");
        goto error;
    } else {
        DEBUG_MSG("dev_con_test --------------> OK\n");
    }

    ret = dev_rsa_test(&data);
    if (!ret) {
        ERROR_MSG("dev_rsa_test --------------> ERROR\n");
    } else {
        DEBUG_MSG("dev_rsa_test --------------> OK\n");
    }

    ret = dev_ecc_test(&data);
    if (!ret) {
        ERROR_MSG("dev_ecc_test --------------> ERROR\n");
    } else {
        DEBUG_MSG("dev_ecc_test --------------> OK\n");
    }

error:
    if (data.hCon1) {
        SKF_CloseContainer(data.hCon1);
        data.hCon1 = NULL;
    }
    if (data.hCon2) {
        SKF_CloseContainer(data.hCon2);
        data.hCon2 = NULL;
    }
    if (data.hApp) {
        SKF_CloseApplication(data.hApp);
        data.hApp = NULL;
    }
    if (data.hDev) {
        SKF_DisConnectDev(data.hDev);
        data.hDev = NULL;
    }

    return 0;
}
