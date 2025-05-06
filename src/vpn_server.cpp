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
        boost::asio::io_context io;
        boost::asio::ssl::context ssl_ctx{boost::asio::ssl::context::tlsv12_server};
        ssl_ctx.use_certificate_chain_file(cert_file);
        ssl_ctx.use_private_key_file(key_file, boost::asio::ssl::context::pem);

        tcp::acceptor acceptor{io, {tcp::v4(), static_cast<unsigned short>(std::stoi(listen_port))}};
        std::cout<<"Waiting for VPN client on port "<<listen_port<<"…\n";
        tcp::socket raw_sock{io};
        acceptor.accept(raw_sock);
        std::cout<<"Client connected, doing TLS handshake…\n";

        boost::asio::ssl::stream<tcp::socket> ssl_sock{std::move(raw_sock), ssl_ctx};
        ssl_sock.handshake(boost::asio::ssl::stream_base::server);
        std::cout<<"TLS handshake complete.\n";


        std::vector<uint8_t> keybuf;
        async_read_frame(ssl_sock, keybuf, [&](auto const& ec, std::size_t) {
            if (ec) {
                std::cerr << "Key exchange failed: " << ec.message() << "\n";
                return;
            }

            std::string key(keybuf.begin(), keybuf.end());
            std::cout << "Key received from client\n";

            // Initialize crypto with the received key
            auto crypto = std::make_shared<CryptoManager>();
            if (!crypto->initialize(key)) {
                std::cerr << "Failed to initialize crypto with received key\n";
                return;
            }



            auto tun = std::make_shared<TunHandler>(io, tun_if, crypto);
            std::cout << "client is using TUN interface " << tun->get_tun_interface() << "\n";
            std::string ifname = tun->get_tun_interface();

            std::system(("sudo ifconfig " + ifname + " 10.8.0.1 10.8.0.2 netmask 255.255.255.255 up").c_str());
            tun->set_tunnel_callback(
                        [&](auto const& pkt){
                            auto ct = crypto->encrypt(pkt);
                            async_write_frame(ssl_sock, ct,
                                [&](auto const& ec, std::size_t){
                                    if (ec) std::cerr<<"server→client write error: "<<ec.message()<<"\n";
                                });
                        });
            tun->start();
            std::system("sysctl -w net.inet.ip.forwarding=1");
            std::system("pfctl -e");
            std::system("echo 'nat on en0 from 10.8.0.0/24 to any -> (en0)' | pfctl -f -");

        std::vector<uint8_t> inbuf;
        std::function<void()> do_read = [&]{
        async_read_frame(ssl_sock, inbuf,
            [&](auto const& ec, std::size_t){
                if(ec){
                    std::cerr<<"client→server read error: "<<ec.message()<<"\n";
                    return;
                }
                std::cout << "Server received encrypted packet: " << inbuf.size() << " bytes" << std::endl;
                auto pt = crypto->decrypt(inbuf);
                std::cout << "Decrypted packet: " << pt.size() << " bytes" << std::endl;
                tun->send_to_tun(pt);
                do_read();
            });
        };
        do_read();
        });

        io.run();







    }catch(std::exception& e){
        std::cerr<<"Exception: "<<e.what()<<"\n";
        return 1;

    }
}
