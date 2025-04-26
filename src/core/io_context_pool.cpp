#include <iostream> 
#include "core/io_context_pool.h"
#include <stdio.h>
#include <vector>
#include <string>

IoContextPool::IoContextPool(std::size_t pool_size){
    for (std::size_t i = 0; i < pool_size; ++i){
        std::cout<< "Creating io_context " << i << std::endl;
        auto io_ctx = std::make_shared<boost::asio::io_context>();
        io_contexts_.push_back(io_ctx);
        std::cout<< "Creating work guard " << i << std::endl;
        work_guards_.emplace_back(boost::asio::make_work_guard(*io_ctx));
        std::cout<< "Creating thread " << i << std::endl;
        
    }
}

void IoContextPool::run(){
    for (auto& io_ctx: io_contexts_){
        std::cout<< "Starting thread " << std::endl;
        threads_.emplace_back([io_ctx](){
            std::cout<< "Running io_context " << std::endl;
            io_ctx->run();
        });
    }
}

void IoContextPool::stop(){
    for (auto& io_ctx: io_contexts_){
        io_ctx->stop();
    }

    for (auto& thread: threads_){
        if (thread.joinable()){
            std::cout<< "Joining thread " << std::endl;
            thread.join();
        }
    }
}

boost::asio::io_context& IoContextPool::get_io_context(){
    std::size_t index = next_++ % io_contexts_.size();
    return *io_contexts_[index];
}