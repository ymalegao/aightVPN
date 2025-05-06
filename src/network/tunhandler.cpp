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

    std::cout << "bytes_transferred size" << bytes_transferred << std::endl;
    if (bytes_transferred <= TUN_HEADER_SIZE){
        async_read_from_tun();
        return;
    }

    const uint8_t* data_start = read_buffer_.data() + TUN_HEADER_SIZE;
    size_t ip_len = bytes_transferred - TUN_HEADER_SIZE;
    std::vector<uint8_t> packet(data_start, data_start + ip_len);

    if (tunnel_callback_){
        std::cout << " tunnel call back exists "  << std::endl;

        tunnel_callback_(packet);
    }else{
        std::cout << "does tunnel call back exist? NO! "  << std::endl;

    }

    async_read_from_tun();

}

void TunHandler::send_to_tun(const std::vector<uint8_t>& packet) {
    std::cout << "TUN " << (send ? "SEND" : "READ") << ": " << packet.size()
              << " bytes, IPv" << ((packet[0] >> 4) & 0xF);
    for(int i = 0; i < std::min(20, (int)packet.size()); i++) {
        std::cout << " " << std::hex << (int)packet[i];
    }
    std::cout << std::dec << std::endl;

    std::vector<uint8_t> buf;
    buf.reserve(packet.size() + TUN_HEADER_SIZE);
    buf.push_back(0);
    buf.push_back(0);
    uint8_t af = (packet.size() >= 1 && (packet[0] >> 4) == 6) ? AF_INET6 : AF_INET;
    buf.push_back(0);
    buf.push_back(static_cast<uint8_t>(af));
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

void TunHandler::add_route_for_domain(const std::string& domain_name,
                                      const std::string& tun_interface)
{
    boost::asio::io_context ctx;
    boost::asio::ip::tcp::resolver r(ctx);
    boost::system::error_code ec;
    auto results = r.resolve(domain_name, "", ec);
    if (ec) return;
    for (auto& entry : results) {
        auto ip = entry.endpoint().address().to_string();
        std::stringstream del, add;
        del << "sudo route delete -host " << ip;
        add << "sudo route add -host " << ip << " -interface " << tun_interface;
        std::system(del.str().c_str());
        std::system(add.str().c_str());
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
