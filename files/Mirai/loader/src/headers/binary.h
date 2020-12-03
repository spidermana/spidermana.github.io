#pragma once

#include "includes.h"

#define BINARY_BYTES_PER_ECHOLINE   128

struct binary {
    char arch[6];
    int hex_payloads_len;   //hex_payloads_len表示hex_payloads有多少个128字节单元【第一维的char*指针有多少】
    char **hex_payloads;    //bins的内容
};

BOOL binary_init(void);
struct binary *binary_get_by_arch(char *arch);

static BOOL load(struct binary *bin, char *fname);
