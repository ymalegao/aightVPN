#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "network/tunhandler.h"
#include "crypto/cryptoManager.h"


using boost::asio::ip::tcp;

template<typename AsyncWriteStream, typename WriteHandler>
void async_write_frame(AsyncWriteStream& sock, const std::vector<uint8_t>& buf, WriteHandler&& handler){
    std::array<uint8_t, 4> header;
    uint32_t N = htonl(static_cast<uint32_t>(buf.size()));
    std::memcpy(header.data(), &N, 4);
    std::vector<boost::asio::const_buffer> bufs = {
        boost::asio::buffer(header),
        boost::asio::buffer(buf)

    };
    boost::asio::async_write(sock, bufs, std::forward<WriteHandler>(handler));


}

template<typename AsyncReadStream, typename ReadHandler>
void async_read_frame(AsyncReadStream& sock, std::vector<uint8_t>& outbuf, ReadHandler&& handler){
    auto len_buf = std::make_shared<std::array<uint8_t, 4>>();
    boost::asio::async_read(sock, boost::asio::buffer(*len_buf), [&, len_buf, handler = std::forward<ReadHandler>(handler)]
        (const boost::system::error_code& ec, std::size_t){
            if (ec) {handler(ec,0); return;}
            uint32_t N;
            std::memcpy(&N, len_buf->data(), 4);
            N = ntohl(N);
            outbuf.resize(N);
            boost::asio::async_read(sock, boost::asio::buffer(outbuf), [handler = std::move(handler)]
                (const boost::system::error_code& ec2, std::size_t n2){
                    handler(ec2, n2);
                });
        });
}

int main(int argc, char* argv[]){
    if (argc!=6) {
            std::cerr<<"Usage: "<<argv[0]<<" <listen_port> <tun_if> <psk> <server.crt> <server.key>\n";
            return 1;
        }
        auto listen_port = argv[1];
        std::string tun_if = argv[2];
        std::string psk    = argv[3];
        std::string cert_file = argv[4];
        std::string key_file  = argv[5];
    try{
        auto io = std::make_shared<boost::asio::io_context>();
        boost::asio::ssl::context ssl_ctx{boost::asio::ssl::context::tlsv12_server};
        ssl_ctx.use_certificate_chain_file(cert_file);
        ssl_ctx.use_private_key_file(key_file, boost::asio::ssl::context::pem);

        tcp::acceptor acceptor{*io, {tcp::v4(), static_cast<unsigned short>(std::stoi(listen_port))}};
        std::cout<<"Waiting for VPN client on port "<<listen_port<<"…\n";
        tcp::socket raw_sock{*io};
        acceptor.accept(raw_sock);
        std::cout<<"Client connected, doing TLS handshake…\n";

        auto ssl_sock = std::make_shared<boost::asio::ssl::stream<tcp::socket>>(std::move(raw_sock), ssl_ctx);
        ssl_sock->handshake(boost::asio::ssl::stream_base::server);
        std::cout<<"TLS handshake complete.\n";


        auto keybuf = std::make_shared<std::vector<uint8_t>>();
        async_read_frame(*ssl_sock, *keybuf, [io, ssl_sock, keybuf, tun_if](auto const& ec, std::size_t) {
            if (ec) {
                std::cerr << "Key exchange failed: " << ec.message() << "\n";
                return;
            }

            std::string key(keybuf->begin(), keybuf->end());
            std::cout << "Key received from client\n";

            // Initialize crypto with the received key
            auto crypto = std::make_shared<CryptoManager>();
            if (!crypto->initialize(key)) {
                std::cerr << "Failed to initialize crypto with received key\n";
                return;
            }



            auto tun = std::make_shared<TunHandler>(*io, tun_if, crypto);
            std::cout << "client is using TUN interface " << tun->get_tun_interface() << "\n";
            std::string ifname = tun->get_tun_interface();

            std::system(("sudo ifconfig " + ifname + " 10.8.0.1 10.8.0.2 netmask 255.255.255.255 up").c_str());

            #if defined(__APPLE__)
                std::system(("sudo ifconfig " + ifname + " 10.8.0.1 10.8.0.2 netmask 255.255.255.255 up").c_str());
                std::system("sudo sysctl -w net.inet.ip.forwarding=1");
                std::system("sudo pfctl -e");
                std::system("echo 'nat on en0 from 10.8.0.0/24 to any -> (en0)' | sudo pfctl -f -");
            #elif defined(__linux__)
                std::system(("sudo ip addr add 10.8.0.1/32 peer 10.8.0.2 dev " + ifname).c_str());
                std::system(("sudo ip link set " + ifname + " up").c_str());
                std::system("sudo sysctl -w net.ipv4.ip_forward=1");

                // Use iptables for NAT
                //std::system("sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE");
            #else
                #error "Unsupported platform"
            #endif

            tun->set_tunnel_callback(
                [crypto, ssl_sock](const std::vector<uint8_t>& pkt){
                    std::cout << "[Server] Entered tunnel callback, pkt size = " << pkt.size() << "\n";

                    if (!crypto) {
                        std::cerr << "[Server] CRITICAL: crypto is null!\n";
                        return;
                    }

                    if (pkt.empty()) {
                        std::cerr << "[Server] Skipping empty packet\n";
                        return;
                    }

                    auto ct = crypto->encrypt(pkt);
                    if (ct.empty()) {
                        std::cerr << "[Server] Crypto returned empty buffer, skipping write.\n";
                        return;
                    }
                    std::cout << "[Server] Encrypted packet of size " << ct.size() << "\n";

                    async_write_frame(*ssl_sock, ct,
                        [](const auto& ec, std::size_t){
                            if (ec) std::cerr << "[Server] Write error: " << ec.message() << "\n";
                        });
                });
            tun->start();

            auto inbuf = std::make_shared<std::vector<uint8_t>>();
            auto do_read = std::make_shared<std::function<void()>>();
            *do_read = [ssl_sock, crypto, tun, inbuf, do_read]() {
                async_read_frame(*ssl_sock, *inbuf,
                [ssl_sock, crypto, tun, inbuf, do_read](const boost::system::error_code& ec, std::size_t){
                    if(ec){
                        std::cerr<<"client→server read error: "<<ec.message()<<"\n";
                        return;
                    }
                    std::cout << "Server received encrypted packet: " << inbuf->size() << " bytes" << std::endl;
                    auto pt = crypto->decrypt(*inbuf);
                    if (pt.empty()) {
                        std::cerr << "Decryption failed or returned empty payload, skipping send_to_tun.\n";
                        return;
                    }
                    tun->send_to_tun(pt);
                    (*do_read)();  // Call through the shared_ptr
                });
        };
        (*do_read)(); // Start the first read
        });

        io->run();
        return 0;







    } catch(std::exception& e){
        std::cerr<<"Exception: "<<e.what()<<"\n";
        return 1;

    }
}
