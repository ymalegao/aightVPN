#include "network/tunhandler.h"
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <netinet/in.h>
#include <iostream>
#include <sstream>
#include <cstdlib>


TunHandler::TunHandler(boost::asio::io_context& io_context,
                       const std::string& device_name,
                       std::shared_ptr<CryptoManager> crypto_manager)
    : io_context_(io_context),
      crypto_manager_(std::move(crypto_manager)),
      tunnel_callback_(),
      tun_stream_(io_context_),
      tun_name{},
      tun_fd_(-1),
      read_buffer_{},
      device_name_(device_name)
{
    tun_fd_ = tunOpen(&tun_name,
                      device_name_.empty() ? nullptr : device_name_.c_str());
    if (tun_fd_ < 0) {
        perror("tunOpen");
        throw std::runtime_error("Failed to open TUN device");
    }

    #if defined(__linux__)
    struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, tun_name.name, IFNAMSIZ - 1);
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (ioctl(tun_fd_, TUNSETIFF, &ifr) < 0) {
               std::cerr << "Warning: Could not set TUN device to NO_PI mode\n";
               // Continue anyway, we'll handle both formats
           } else {
               std::cout << "TUN device set to NO_PI mode (no packet info header)\n";
           }
    #endif
    tun_stream_.assign(tun_fd_);
    std::cout << "Opened TUN '" << device_name_
              << "' as '" << tun_name.name << "'\n";
}
TunHandler::~TunHandler() {

}

void TunHandler::start() {
    async_read_from_tun();
}

void TunHandler::async_read_from_tun(){
    auto self = shared_from_this();
    tun_stream_.async_read_some(boost::asio::buffer(read_buffer_),
        [this, self](const boost::system::error_code&ec, std::size_t n){
            std::cout << "Handling_reda" << std::endl;
            handle_read(ec, n);
        }
    );
}

void TunHandler::handle_read(const boost::system::error_code& ec, std::size_t bytes_transferred) {
    if (ec){
            std::cerr << "Error reading from TUN device: " << ec.message() << std::endl;
            return;
    }

    std::cout << "[TUN] Read " << bytes_transferred << " bytes from TUN\n";

    size_t header_size = 0;
    #if defined(__APPLE__)
    header_size = TUN_HEADER_SIZE;  // 4 bytes on macOS
    #elif defined(__linux__)

    if (bytes_transferred > 4 && (read_buffer_[0] & 0xF0) != 0x40 && (read_buffer_[0] & 0xF0) != 0x60) {
            // This doesn't look like an IPv4 or IPv6 packet, assume 4-byte header
            header_size = 4;
        }
    #endif
    if (bytes_transferred <= header_size){
            std::cout << "[TUN] Packet too small (only " << bytes_transferred << " bytes), skipping\n";
            async_read_from_tun();
            return;
    }

    const uint8_t* data_start = read_buffer_.data() + header_size;
    size_t ip_len = bytes_transferred - header_size;

    std::cout << "[TUN] IP packet: ";
       for (size_t i = 0; i < std::min<size_t>(ip_len, 16); ++i) {
           printf("%02x ", data_start[i]);
       }
       std::cout << std::endl;


       uint8_t version = (data_start[0] >> 4) & 0xF;
          if (version != 4 && version != 6) {
              std::cerr << "[TUN] Invalid IP version: " << +version << ", skipping packet\n";
              async_read_from_tun();
              return;
          }



          std::vector<uint8_t> packet(data_start, data_start + ip_len);

             if (tunnel_callback_){
                 tunnel_callback_(packet);
             }

             async_read_from_tun();


}

void TunHandler::send_to_tun(const std::vector<uint8_t>& packet) {
    if (packet.empty()) return;
    uint8_t version = (packet[0] >> 4) & 0xF;
       if (version != 4 && version != 6) {
           std::cerr << "[TUN] Skipping non-IP packet (version = " << +version << ")\n";
           return;
       }
    std::cout << "TUN " << (send ? "SEND" : "READ") << ": " << packet.size()
              << " bytes, IPv" << ((packet[0] >> 4) & 0xF);
    for(int i = 0; i < std::min(20, (int)packet.size()); i++) {
        std::cout << " " << std::hex << (int)packet[i];
    }
    std::cout << std::dec << std::endl;

    std::vector<uint8_t> buf;
    #if defined (__APPLE__)
    buf.reserve(packet.size() + TUN_HEADER_SIZE);
    buf.push_back(0);
    buf.push_back(0);
    uint8_t af = (packet.size() >= 1 && (packet[0] >> 4) == 6) ? AF_INET6 : AF_INET;
    buf.push_back(0);
    buf.push_back(static_cast<uint8_t>(af));
    #else
    buf.reserve(packet.size());
    #endif

    buf.insert(buf.end(), packet.begin(), packet.end());

    auto self = shared_from_this();
    boost::asio::async_write(
        tun_stream_, boost::asio::buffer(buf),
        [self](const boost::system::error_code& ec, std::size_t){
            if (ec){
                std::cerr << "Error writing to TUN device: " << ec.message() << std::endl;
            }
        }
    );

}

void TunHandler::set_tunnel_callback(TunnelCallback cb) {
    tunnel_callback_ = std::move(cb);
}


std::string TunHandler::get_tun_interface() const {
    return std::string(tun_name.name);
}

void TunHandler::add_route_for_domain(boost::asio::io_context& io_context, const std::string& domain_name, const std::string& tun_interface) {
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::system::error_code ec;

    auto results = resolver.resolve(domain_name, "", ec);
    if (ec) {
        std::cerr << "[VPN] Failed to resolve domain name: " << domain_name << ", error = " << ec.message() << std::endl;
        return;
    }

    for (const auto& entry : results){
        auto ip_address = entry.endpoint().address().to_string();

        std::cout << "[VPN][ROUTE] Resolved " << domain_name << " -> " << ip_address << std::endl;

        // Delete any existing route to that host
        std::stringstream del_cmd;
        del_cmd << "sudo route delete -host " << ip_address;
        std::cout << "[VPN][ROUTE] Deleting old route: " << del_cmd.str() << std::endl;
        std::system(del_cmd.str().c_str());

        // Add route via TUN interface
        std::stringstream add_cmd;
        add_cmd << "sudo route add -host " << ip_address << " -interface " << tun_interface;
        std::cout << "[VPN][ROUTE] Adding new route: " << add_cmd.str() << std::endl;
        std::system(add_cmd.str().c_str());

        break; // Route only first resolved IP (usually good enough)
    }
}



void TunHandler::remove_route_for_domain(const std::string& domain_name,
                                         const std::string& tun_interface)
{
    boost::asio::io_context ctx;
    boost::asio::ip::tcp::resolver r(ctx);
    boost::system::error_code ec;
    auto results = r.resolve(domain_name, "", ec);
    if (ec) return;
    for (auto& entry : results) {
        auto ip = entry.endpoint().address().to_string();
        std::stringstream del;
        del << "sudo route delete -host " << ip;
        std::system(del.str().c_str());
    }
}
