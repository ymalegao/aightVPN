#include <iostream>
// #include "core.h"
#include <stdio.h>
#include <vector>
#include <string>
#include <atomic>
#include <boost/asio.hpp>
#include <core/io_context_pool.h>
#include "network/server.h"
#include "network/session.h"
#include "crypto/cryptoManager.h"
#include "network/fakeVpnTunnel.h"

using boost::asio::ip::tcp;

int main( ) {
   try{

       auto crypto_manager = std::make_shared<CryptoManager>();
       std::string encryption_key = CryptoManager::generate_key();
       std::cout << "Using encryption key: ";
               for (char c : encryption_key) {
                   printf("%02x", (unsigned char)c);
               }
               std::cout << std::endl;

        if (!crypto_manager->initialize(encryption_key)) {
            std::cerr << "Failed to initialize crypto manager" << std::endl;
            return 1;
        }
       IoContextPool pool(4); // create a pool of 4 io_contexts

        auto& main_io_context = pool.get_io_context(); // get the main io_context


        boost::asio::io_context tun_io_context;

        std::thread tun_thread([&]() {
            std::cout << "TUN thread running" << std::endl;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
                    work_guard(tun_io_context.get_executor());
            tun_io_context.run();
            std::cout << "TUN thread stopped" << std::endl;
        });

        Server server(main_io_context,tun_io_context, 12345, crypto_manager); // create a server instance on port 12345
        auto fake_tunnel = std::make_shared<FakeVpnTunnel>(tun_io_context);
        fake_tunnel->set_crypto(crypto_manager);
        server.set_tunnel(fake_tunnel);


        pool.run(); // run the io_context pool to start the server
        std::cout << "Server is running on port 12345" << std::endl;
        main_io_context.run(); // run the io_context to start accepting connections
        tun_thread.join();

    //use ;; because the loop is infinite and we want to keep the server running while accepting connections

   } catch (std::exception& e){
        std::cerr << "Exception : " << e.what() << std::endl;
   }
   return 0;

}
