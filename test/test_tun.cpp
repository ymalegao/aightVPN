#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <core/tun_device.h>

int main() {
    TunOpenName tun_name;

    int fd = tunOpen(&tun_name, nullptr);
    if (fd < 0) {
        std::cerr << "Failed to open TUN device: " << strerror(errno) << std::endl;
        return 1;
    }

    std::cout << "Opened TUN device: " << tun_name.name << std::endl;

    // Set non-blocking
    fcntl(fd, F_SETFL, O_NONBLOCK);

    uint8_t buffer[2000];

    while (true) {
        int n = read(fd, buffer, sizeof(buffer));
        if (n > 0) {
            std::cout << "[TUN DEBUG] Read " << n << " bytes: ";
            for (int i = 0; i < n; ++i) {
                printf("%02x ", buffer[i]);
            }
            std::cout << std::endl;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    close(fd);
    return 0;
}
