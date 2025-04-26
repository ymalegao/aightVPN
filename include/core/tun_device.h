#pragma once

#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>


struct TunOpenName{
    char name[16];
};

int tunOpen(TunOpenName *name, const char* name_hint);

#define TUN_OPEN_PACKET_OFFSET 4
#include <sys/socket.h>
#define TUN_OPEN_IP4_HEADER 0x00, 0x00, 0x00, AF_INET
#define TUN_OPEN_IS_IP4(buf) (((const unsigned char*) buf)[3] == AF_INET)
#define TUN_OPEN_IP6_HEADER 0x00, 0x00, 0x00, AF_INET6
#define TUN_OPEN_IS_IP6(buf) (((const unsigned char*) buf)[3] == AF_INET6)
