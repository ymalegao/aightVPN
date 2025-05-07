#pragma once

#include <cstring>
#include <cerrno>

struct TunOpenName {
#if defined(__APPLE__)
    char name[16];
#elif defined(__linux__)
    char name[IFNAMSIZ];
#endif
};

// Helper macro to evaluate system calls
#define CHK(var, call) do { var = call; if (var < 0) return -1; } while (0)

#if defined(__APPLE__)

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>

int tunOpen(TunOpenName* tun_name_out, const char* name_hint) {
    uint32_t numdev = 0;

    if (name_hint) {
        if (strncmp(name_hint, "utun", 4) != 0 || name_hint[4] == '\0') {
            errno = EINVAL;
            return -1;
        }

        for (const char* p = name_hint + 4; *p; ++p) {
            if (*p < '0' || *p > '9') {
                errno = EINVAL;
                return -1;
            }
            numdev = numdev * 10 + (*p - '0');
        }
        numdev += 1;  // utun<N>: utun0 = unit 1
    }

    int fd;
    CHK(fd, socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL));

    struct ctl_info info = {};
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    int err;
    CHK(err, ioctl(fd, CTLIOCGINFO, &info));

    struct sockaddr_ctl addr = {};
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = numdev;

    CHK(err, connect(fd, (struct sockaddr*)&addr, sizeof(addr)));

    if (tun_name_out) {
        socklen_t optlen = sizeof(tun_name_out->name);
        CHK(err, getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, tun_name_out->name, &optlen));
    }

    return fd;
}

#elif defined(__linux__)

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
struct TunOpenName {
    char name[IFNAMSIZ];
};

int tunOpen(TunOpenName* tun_name_out, const char* name_hint) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return -1;

    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (name_hint && *name_hint) {
        std::strncpy(ifr.ifr_name, name_hint, IFNAMSIZ);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }

    if (tun_name_out) {
        std::strncpy(tun_name_out->name, ifr.ifr_name, sizeof(tun_name_out->name));
    }

    return fd;
}

#else
#error "tunOpen is not implemented for this platform"
#endif
