#pragma once

#include "includes.h"

struct resolv_entries {   //存储ip和对应ip的长度
    uint8_t addrs_len;
    ipv4_t *addrs;
};

void resolv_domain_to_hostname(char *, char *);
struct resolv_entries *resolv_lookup(char *);
void resolv_entries_free(struct resolv_entries *);
