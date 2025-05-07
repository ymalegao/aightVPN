#pragma once

#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

// TUN-specific macros
#define TUN_OPEN_PACKET_OFFSET 4
#define TUN_OPEN_IP4_HEADER 0x00, 0x00, 0x00, AF_INET
#define TUN_OPEN_IS_IP4(buf) (((const unsigned char*) buf)[3] == AF_INET)
#define TUN_OPEN_IP6_HEADER 0x00, 0x00, 0x00, AF_INET6
#define TUN_OPEN_IS_IP6(buf) (((const unsigned char*) buf)[3] == AF_INET6)

#ifdef __APPLE__

#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>

struct TunOpenName {
    char name[16];
};

// macOS-only tunOpen function declaration
int tunOpen(TunOpenName* name, const char* name_hint);

#else

// Placeholder for Linux struct and function — define if needed later
struct TunOpenName {
    char name[16];
};

// On Linux, you typically open /dev/net/tun, not via sysctl
int tunOpen(TunOpenName* name, const char* name_hint);

#endif
