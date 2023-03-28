#include <cassert>
#include <cstring>
#include <limits>
#include <net/udp.hpp>

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

net::Result<net::SocketAddr> sockaddr_to_addr(
    const sockaddr_storage& addr, size_t len)
{
    if (addr.ss_family == AF_INET) {
        if (len < sizeof(sockaddr_in)) {
            return tl::make_unexpected(
                std::make_error_code(std::errc::bad_address));
        }

        const auto& addr_in = *reinterpret_cast<const sockaddr_in*>(&addr);

        std::array<std::byte, 4> octets {};
        uint16_t port { ntohs(addr_in.sin_port) };

        std::memcpy(octets.data(), &addr_in.sin_addr, 4);

        return net::SocketAddrV4::create(net::Ipv4Addr::create(octets), port);
    }

    if (addr.ss_family == AF_INET6) {
        if (len < sizeof(sockaddr_in6)) {
            return tl::make_unexpected(
                std::make_error_code(std::errc::bad_address));
        }

        const auto& addr_in6 = *reinterpret_cast<const sockaddr_in6*>(&addr);

        std::array<std::byte, 16> octets {};
        uint16_t port { ntohs(addr_in6.sin6_port) };

        std::memcpy(octets.data(), &addr_in6.sin6_addr, 16);

        return net::SocketAddrV6::create(net::Ipv6Addr::create(octets), port);
    }

    return tl::make_unexpected(get_last_error());
}

template<typename F>
net::Result<net::SocketAddr> do_something_with_sockaddr(F&& f)
{
    sockaddr_storage addr_storage {};
    socklen_t addr_len = sizeof(addr_storage);

    if (!f(reinterpret_cast<sockaddr*>(&addr_storage), &addr_len)) {
        return tl::make_unexpected(get_last_error());
    }

    const auto addr = sockaddr_to_addr(addr_storage, addr_len);

    if (!addr) {
        return tl::make_unexpected(addr.error());
    }

    return *addr;
}
} // namespace

namespace net {
Result<UdpSocket> UdpSocket::bind(SocketAddr addr)
{
    auto sock = Socket::create(addr, Socket::Type::Dgram);

    if (!sock) {
        return tl::make_unexpected(sock.error());
    }

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

    return UdpSocket { std::move(*sock) };
}

Result<SocketAddr> UdpSocket::peer_addr() const
{
    return do_something_with_sockaddr(
        [this](sockaddr* addr, socklen_t* addr_len) {
            return ::getpeername(m_inner.as_raw_socket(), addr, addr_len) != -1;
        });
}

Result<SocketAddr> UdpSocket::socket_addr() const
{
    return do_something_with_sockaddr(
        [this](sockaddr* addr, socklen_t* addr_len) {
            return ::getsockname(m_inner.as_raw_socket(), addr, addr_len) != -1;
        });
}

Result<size_t> UdpSocket::send_to(
    tcb::span<const std::byte> buf, SocketAddr addr) const
{
    const auto len = static_cast<int>((std::min)(
        buf.size(), static_cast<size_t>((std::numeric_limits<int>::max)())));
    size_t ret {};

    if (const auto res = addr_to_sockaddr(addr,
            [this, &buf, len, &ret](
                const sockaddr* addr_in, socklen_t addr_len) -> Result<void> {
#ifdef _WIN32
                using sendto_t = int;
#else
                    using sendto_t = size_t;
#endif

                const auto sent = ::sendto(m_inner.as_raw_socket(),
                    reinterpret_cast<const char*>(buf.data()),
                    static_cast<sendto_t>(len), MSG_NOSIGNAL, addr_in,
                    addr_len);

                if (sent == -1) {
                    return tl::make_unexpected(get_last_error());
                }

                ret = static_cast<size_t>(sent);
                return {};
            });
        !res) {
        return tl::make_unexpected(res.error());
    }

    return ret;
}

Result<void> UdpSocket::connect(SocketAddr addr) const
{
    if (const auto res = addr_to_sockaddr(addr,
            [this](
                const sockaddr* addr_in, socklen_t addr_len) -> Result<void> {
                if (::connect(m_inner.as_raw_socket(), addr_in, addr_len)
                    == -1) {
                    return tl::make_unexpected(get_last_error());
                }

                return {};
            });
        !res) {
        return tl::make_unexpected(res.error());
    }

    return {};
}
} // namespace net
