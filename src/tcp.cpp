#include <cassert>
#include <cstring>
#include <net/tcp.hpp>
#include <numeric>

#ifdef _WIN32
#include <WS2tcpip.h>
#include <WinSock2.h>

static constexpr int
    MSG_NOSIGNAL {}; // MSG_NOSIGNAL is not supported on Windows.
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace {
std::error_code get_last_error()
{
#ifdef _WIN32
    const auto error = WSAGetLastError();
    return std::error_code { error, std::system_category() };
#else
    const auto error = errno;
    return std::error_code { error, std::generic_category() };
#endif
}

template<typename T> bool setsockopt(
    const net::Socket& sock, int level, int option_name, T option_value)
{
    return ::setsockopt(sock.as_raw_socket(), level, option_name,
               reinterpret_cast<const char*>(&option_value),
               sizeof(option_value))
        != -1;
}

template<typename F>
net::Result<void> addr_to_sockaddr(const net::SocketAddr& addr, F&& f)
{
    if (addr.is_ipv4()) {
        sockaddr_in addr_in {};
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = htons(addr.port());

        std::memcpy(&addr_in.sin_addr, addr.ipv4().octets().data(), 4);
        return f(reinterpret_cast<sockaddr*>(&addr_in), sizeof(addr_in));
    }

    sockaddr_in6 addr_in6 {};
    addr_in6.sin6_family = AF_INET6;
    addr_in6.sin6_port = htons(addr.port());

    std::memcpy(addr_in6.sin6_addr.s6_addr, addr.ipv6().octets().data(), 16);
    return f(reinterpret_cast<sockaddr*>(&addr_in6), sizeof(addr_in6));
}
} // namespace

namespace net {
Result<TcpStream> TcpStream::connect(SocketAddr addr)
{
    auto sock = Socket::create(addr, Socket::Type::Stream);

    if (!sock) {
        return tl::make_unexpected(sock.error());
    }

    if (const auto res = addr_to_sockaddr(addr,
            [&sock](
                const sockaddr* addr_in, socklen_t addr_len) -> Result<void> {
                if (::connect(sock->as_raw_socket(), addr_in, addr_len) == -1) {
                    return tl::make_unexpected(get_last_error());
                }

                return {};
            });
        !res) {
        return tl::make_unexpected(res.error());
    }

    return TcpStream { std::move(*sock) };
}

Result<TcpListener> TcpListener::bind(SocketAddr addr)
{
    auto sock = Socket::create(addr, Socket::Type::Stream);

    if (!sock) {
        return tl::make_unexpected(sock.error());
    }

#ifndef _WIN32
    setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, 1);
#endif

    // Bind our new socket
    if (const auto res = addr_to_sockaddr(addr,
            [&sock](
                const sockaddr* addr_in, socklen_t addr_len) -> Result<void> {
                if (::bind(sock->as_raw_socket(), addr_in, addr_len) == -1) {
                    return tl::make_unexpected(get_last_error());
                }

                return {};
            });
        !res) {
        return tl::make_unexpected(res.error());
    }

    // Start listening
    if (static constexpr int DEFAULT_BACKLOG { 128 };
        ::listen(sock->as_raw_socket(), DEFAULT_BACKLOG) == -1) {
        return tl::make_unexpected(get_last_error());
    }

    return TcpListener { std::move(*sock) };
}

Result<std::pair<TcpStream, SocketAddr>> TcpListener::accept() const
{
    auto res = m_inner.accept();

    if (!res) {
        return tl::make_unexpected(res.error());
    }

    auto& [sock, addr] = *res;

    return std::make_pair(TcpStream { std::move(sock) }, addr);
}
} // namespace net
