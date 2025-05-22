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
void async_write_frame(AsyncWriteStream& sock, const std::vector<uint8_t>&buf, WriteHandler&& handler){
    std::array<uint8_t,4> header;
    uint32_t N = htonl(static_cast<uint32_t>(buf.size()));
    std::memcpy(header.data(), &N, 4);
    std::vector<boost::asio::const_buffer> bufs = {
        boost::asio::buffer(header),
        boost::asio::buffer(buf)
    };
    boost::asio::async_write(sock, bufs, std::forward<WriteHandler>(handler));
}

template<typename AsyncReadStream, typename ReadHandler>
void async_read_frame(AsyncReadStream& sock, std::vector<uint8_t>&outbuf, ReadHandler&& handler){
    auto len_buf = std::make_shared<std::array<uint8_t, 4>>();
    boost::asio::async_read(sock, boost::asio::buffer(*len_buf),
    [&, len_buf, handler = std::forward<ReadHandler>(handler)](const boost::system::error_code& ec, std::size_t bytes_transferred){
        if (ec) { handler(ec, 0); return; }
        uint32_t N;
        std::memcpy(&N, len_buf->data(), 4);
        N = ntohl(N);
        outbuf.resize(N);

        boost::asio::async_read(sock, boost::asio::buffer(outbuf),[handler = std::move(handler)](const boost::system::error_code& ec, std::size_t n2){
            handler(ec, n2);
                }
            );

    });
}

int main(int argc, char* argv[]){
    if (argc != 4) {
            std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <tun_if>\n";
            return 1;
    }

    std::string server_ip = argv[1];
    unsigned short port = static_cast<unsigned short>(std::stoi(argv[2]));
    std::string tun_if = argv[3];

    try{
        boost::asio::io_context io;
        boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv12_client);
        ssl_ctx.load_verify_file("ca.crt");
        // ssl_ctx.set_verify_mode(boost::asio::ssl::verify_peer);


        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(server_ip, std::to_string(port));
        for (auto e: endpoints){
            std::cout << "E is " << e.endpoint() << std::endl;

        }

        boost::asio::ssl::stream<tcp::socket> ssl_sock(io, ssl_ctx);
        boost::asio::connect(ssl_sock.next_layer(), endpoints);
        ssl_sock.handshake(boost::asio::ssl::stream_base::client);
        std::cout << "TLS handshake completed with " << server_ip << ":" << port << "\n";

        auto crypto = std::make_shared<CryptoManager>();
        std::string key = CryptoManager::generate_key(32);
        if (!crypto->initialize(key)) {
            std::cerr << "Failed to initialize CryptoManager\n";
            return 1;
        }

        async_write_frame(ssl_sock,
                          std::vector<uint8_t>(key.begin(), key.end()),
                          [](auto const& ec, std::size_t){});

        auto tun = std::make_shared<TunHandler>(io, tun_if, crypto);
        std::string ifname = tun->get_tun_interface();

        #if defined(__APPLE__)
            std::system(("sudo ifconfig " + ifname +
                        " 10.8.0.2 10.8.0.1 netmask 255.255.255.255 up").c_str());
            // Don't add default route yet
        #elif defined(__linux__)
            std::system(("sudo ip addr add 10.8.0.2/32 peer 10.8.0.1 dev " + ifname).c_str());
            std::system(("sudo ip link set " + ifname + " up").c_str());
            // Don't add default route yet
        #else
            #error "Unsupported platform"
        #endif

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        std::string cmd = "host example.com | grep 'has address' | awk '{print $4}' | "
                         "xargs -I {} sudo route -n add -host {} -interface " + ifname;
        std::system(cmd.c_str());
        std::cout << "Added routes for example.com\n";


        tun->set_tunnel_callback(
            [&](const std::vector<uint8_t>& pkt){

                auto ct = crypto->encrypt(pkt);
                if (ct.empty()) {
                    std::cerr << "encrpytion failed or returned empty payload, skipping send_to_tun.\n";
                    return;
                }
                std::cout << "encrypted packet and writing" << std::endl;
                async_write_frame(ssl_sock, ct, [&](const boost::system::error_code& ec, std::size_t ){
                    if (ec) std::cerr << "Write error: " << ec.message() << "\n";

                });
            });
        tun->start();

        std::vector<uint8_t> inbuf;
        std::function<void()> do_read = [&]{
            async_read_frame(ssl_sock, inbuf, [&](const boost::system::error_code& ec, std::size_t ){
                if (ec) std::cerr << "Read error: " << ec.message() << "\n";
                auto pt = crypto->decrypt(inbuf);
                if (pt.empty()) {
                    std::cerr << "Decryption failed or returned empty payload, skipping send_to_tun.\n";
                    do_read();
                    return;
                }

                std::cout << "[Client] Received decrypted data (" << pt.size() << " bytes): ";
                for (size_t i = 0; i < std::min<size_t>(pt.size(), 16); ++i) {
                    printf("%02x ", pt[i]);
                }
                std::cout << "\n";

                uint8_t version = (pt[0] >> 4) & 0xF;
                if (version == 4 || version == 6) {
                    std::cout << "[Client] Valid IPv" << +version << " packet, sending to TUN\n";
                    tun->send_to_tun(pt);
                }
                else if(pt.size() > 4){
                    version = (pt[4] >> 4) & 0xF;
                    if (version == 4 || version == 6) {
                        std::vector<uint8_t> ip_pkt(pt.begin() + 4, pt.end());
                        std::cout << "[Client] Found IPv" << +version << " after 4-byte header\n";
                        tun->send_to_tun(ip_pkt);
                    }
                    else if (pt.size() >= 24 && (pt[20] == 0x00 || pt[20] == 0x08) && pt[21] == 0x00) {
                        std::cout << "[Client] Possible ICMP packet found at offset 20\n";
                        // Construct valid IPv4 ICMP packet
                        std::vector<uint8_t> icmp_pkt = {
                            0x45, 0x00, 0x00, static_cast<uint8_t>(pt.size() - 16), // IPv4 header
                            0x00, 0x00, 0x00, 0x00, // ID, flags
                            0x40, 0x01, 0x00, 0x00, // TTL, proto (ICMP), checksum
                            0x0a, 0x08, 0x00, 0x01, // Source: 10.8.0.1
                            0x0a, 0x08, 0x00, 0x02  // Dest: 10.8.0.2
                        };
                        // Add ICMP payload
                        icmp_pkt.insert(icmp_pkt.end(), pt.begin() + 20, pt.end());
                        tun->send_to_tun(icmp_pkt);
                    }
                    else{
                        std::cout << "[Client] Unrecognized packet format, skipping\n";
                        tun->send_to_tun(pt);
                    }

                }
                do_read();


                });
        };

                do_read();


                // 7) Run
        io.run();

    }
    catch (std::exception& e) {
            std::cerr << "Exception: " << e.what() << "\n";
            return 1;
        }
    return 0;

}
