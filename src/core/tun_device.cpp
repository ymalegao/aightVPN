#include <core/tun_device.h>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>

// Helper macro to evaluate system calls
#define CHK(var, call) do { var = call; if (var < 0) return -1; } while (0)

int tunOpen(TunOpenName* tun_name_out, const char* name_hint) {
    uint32_t numdev = 0;

    // Parse optional device number from "utun<N>" format
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
        numdev += 1;  // utun<N>: add 1 since utun0 = numdev = 1
    }

    int fd;
    CHK(fd, socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL));

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
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
