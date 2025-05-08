#pragma once

#pragma once

#include <boost/asio.hpp>
#include <array>
#include <functional>
#include <string>
#include <vector>
#include "core/tun_device.h"
#include "crypto/cryptoManager.h"


class TunHandler : public std::enable_shared_from_this<TunHandler>{
    public:
        using TunnelCallback = std::function<void(const std::vector<uint8_t>&)>;

        TunHandler(boost::asio::io_context& io_context, const std::string& device_name,std::shared_ptr<CryptoManager> crypto_manager = nullptr );
        ~TunHandler();

        void start();  // Begin reading from the TUN device

        void send_to_tun(const std::vector<uint8_t>& system_payload);

        void set_tunnel_callback(TunnelCallback cb);

        std::string get_tun_interface() const;

        static void add_route_for_domain(boost::asio::io_context& io_context, const std::string& domain_name,const std::string& tun_interface);

        static void remove_route_for_domain(const std::string& domain_name,const std::string& tun_interface);



        private:

            void async_read_from_tun();
            void handle_read(const boost::system::error_code& ec, std::size_t bytes_transferred);
            boost::asio::io_context& io_context_;
            std::shared_ptr<CryptoManager> crypto_manager_;
            TunnelCallback tunnel_callback_;
            boost::asio::posix::stream_descriptor  tun_stream_;
            TunOpenName tun_name;
            int tun_fd_;
            std::array<uint8_t, 4096> read_buffer_;
            std::string device_name_;
            static constexpr size_t TUN_HEADER_SIZE = 4;  // utun prefix length on macOS



};
