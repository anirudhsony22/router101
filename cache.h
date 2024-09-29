// cache.h
#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>
#include <time.h>

struct arpcache{
    uint32_t ipaddr; // big-indian
    uint8_t  ether_dhost[6];
    time_t timestamp;
    struct arpcache* next;
};

struct ipcache{
    char *interface;
    uint8_t *packet;
    unsigned int len;
    struct ipcache* next;
};

struct cache{
    struct arpcache* arpcacheheader;
    uint16_t arpcachelength;
    uint16_t ipcachelength;
    struct ipcache* ipcacheheader;
};

#endif // CACHE_H