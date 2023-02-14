#include <net/udp.hpp>
#include <thread>

using net::Socket;
using net::SocketAddr;
using net::UdpSocket;

int main()
{
    auto listener = UdpSocket::bind(*SocketAddr::parse("0.0.0.0:3030"));

    if (!listener) {
        std::printf(
            "Failed to bind socket: %s", listener.error().message().c_str());
        return 1;
    }

    if (const auto res = listener->socket().set_nonblocking(true); !res) {
        std::printf("Failed to set socket to non-blocking: %s",
            res.error().message().c_str());
        return 1;
    }

    while (true) {
        std::array<std::byte, 1024> buf {};

        if (const auto res = listener->socket().poll(
                Socket::PollTimeout::Infinite, Socket::PollEvent::Read);
            !res) {
            std::printf(
                "Failed to poll socket: %s", res.error().message().c_str());
            return 1;
        }

        auto recv_res = listener->recv_from(buf);

        if (!recv_res) {
            std::printf("Failed to receive data: %s",
                recv_res.error().message().c_str());
            return 1;
        }

        const auto& [n, from] = *recv_res;

        std::printf(
            "Received %zu bytes from %s\n", n, from.to_string().c_str());
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}
