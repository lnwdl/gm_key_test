/*
 * Copyright (c) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * utils functions.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdkey.h>

void ShwHexBuf(const unsigned char *buf, const size_t len)
{
    size_t i, j;
 
    if (NULL == buf) {
        ERROR_MSG("ShwHexBuf's parameter @buf is ERROR\n");
        return;
    }
 
    fprintf(stdout, "============[%d]==============\n", len);
    for (i = 0, j = 0; i < len; ++i, ++j) {
        if (!(j % 16)) { /* line number */
            if (!j) {
                fprintf(stdout, "%08x:  ", j);
            } else {
                fprintf(stdout, "\n%08x:  ", j);
            }
        }
        fprintf(stdout, "%02x ", buf[i]);
    }
    fprintf(stdout, "\n============================\n");
    fflush(stdout);
 
    return;
}

int GetInput(const char *prompt, char *out, size_t outlen)
{
    char buf[128];
    int len;

    if (prompt) {
        printf("%s\n", prompt);
    }

    scanf("%s", buf);
    len = strlen(buf);
    buf[len] = '\0';

    len = len > outlen ? outlen : len;
    memcpy(out, buf, len + 1);

    return 1;
}

int NameListShow(const char *name_list, const size_t list_len)
{
    const char *end = name_list + list_len;
    size_t len;
    int num = 0;

    while (name_list < end) {
        len = strlen(name_list);
        if (len) {
            printf("\t[%s]\n", name_list);
            num++;
            name_list += len + 1;
        } else {
            name_list++;
        }
    }

    return num;
}

const char *NameListFind(const char *name_list, const size_t list_len, 
        const char *name)
{
    const char *end = name_list + list_len;
    size_t len;

    if (!name) { /* if NULL, use the first list element default */
        return name_list;
    }

    while (name_list < end) {
        len = strlen(name_list);
        if (len) {
            if (!strcmp(name_list, name)) {
                return name;
            }

            name_list += len + 1;
        } else {
            name_list++;
        }
    }

    return NULL;
}
