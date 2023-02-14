#include <iostream>
#include <net/tcp.hpp>

using net::Socket;
using net::SocketAddr;
using net::TcpStream;

int main()
{
    auto client = TcpStream::connect(*SocketAddr::parse("127.0.0.1:8080"));

    if (!client) {
        std::cout << "Error: " << client.error().message() << '\n';
        return 1;
    }

    (void)client->set_nonblocking(true);

    while (true) {
        std::printf("Waiting for data...\n");

        const auto poll_res = client->socket().poll(
            Socket::PollTimeout::Infinite, Socket::PollEvent::Read);

        if (!poll_res) {
            std::cout << "Error: " << poll_res.error().message() << '\n';
            return 1;
        }

        std::array<char, 1024> buf {};
        const auto read_res
            = client->read(std::as_writable_bytes(std::span(buf)));

        if (!read_res) {
            std::cout << "Error: " << read_res.error().message() << '\n';
            return 1;
        }

        if (*read_res == 0) {
            std::printf("Connection closed by peer\n");
            return 0;
        }

        std::cout << "Received: " << std::string_view(buf.data(), *read_res)
                  << '\n';
    }
}
