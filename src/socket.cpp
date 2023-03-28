#include <cassert>
#include <cstring>
#include <limits>
#include <net/socket.hpp>

#ifdef _WIN32
#include <WS2tcpip.h>
#include <WinSock2.h>

#undef INVALID_SOCKET
static constexpr int
    MSG_NOSIGNAL {}; // MSG_NOSIGNAL is not supported on Windows.

#define SYS_CLOSE_SOCKET ::closesocket
#define SYS_POLL ::WSAPoll
#else
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define SYS_CLOSE_SOCKET ::close
#define SYS_POLL ::poll
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

void init()
{
    [[maybe_unused]] static const auto _ = [] {
#ifdef _WIN32
        WSADATA wsa_data {};
        [[maybe_unused]] const auto res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        assert(res == 0);
#endif
        return 0;
    }();
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

#if defined(__APPLE__) && defined(__MACH__)
constexpr size_t MAX_READ_SIZE = (std::numeric_limits<int>::max)() - 1;
#elif defined(_WIN32)
constexpr size_t MAX_READ_SIZE = (std::numeric_limits<int>::max)();
#else
constexpr size_t MAX_READ_SIZE = (std::numeric_limits<ssize_t>::max)();
#endif
} // namespace

namespace net {
Socket::Socket(Socket&& other) noexcept
{
    if (m_socket != INVALID_SOCKET) {
        SYS_CLOSE_SOCKET(m_socket);
    }

    if (other.m_socket != INVALID_SOCKET) {
        m_socket = other.m_socket;
        other.m_socket = INVALID_SOCKET;
    }
}

Socket& Socket::operator=(Socket&& other) noexcept
{
    if (this != &other) {
        if (m_socket != INVALID_SOCKET) {
            SYS_CLOSE_SOCKET(m_socket);
        }

        if (other.m_socket != INVALID_SOCKET) {
            m_socket = other.m_socket;
            other.m_socket = INVALID_SOCKET;
        }
    }

    return *this;
}

Socket::~Socket()
{
    if (m_socket != INVALID_SOCKET) {
        SYS_CLOSE_SOCKET(m_socket);
    }
}

Result<Socket> Socket::create(SocketAddr addr, Type type)
{
    return addr.is_ipv4() ? create_raw(Domain::Ipv4, type)
                          : create_raw(Domain::Ipv6, type);
}

Result<Socket> Socket::create_raw(Domain family, Type type)
{
    init();

    if (family != Domain::Ipv4 && family != Domain::Ipv6) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    const auto family_inner = family == Domain::Ipv4 ? AF_INET : AF_INET6;

    if (type != Type::Stream && type != Type::Dgram && type != Type::SeqPacket
        && type != Type::Raw) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    const auto type_inner = [type] {
        switch (type) {
        case Type::Stream:
            return SOCK_STREAM;
        case Type::Dgram:
            return SOCK_DGRAM;
        case Type::SeqPacket:
            return SOCK_SEQPACKET;
        case Type::Raw:
            return SOCK_RAW;
        }

        // unreachable
        return SOCK_STREAM;
    }();

#ifdef _WIN32
    auto sock = WSASocketW(family_inner, type_inner, 0, nullptr, 0,
        WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
#else
#ifdef SOCK_CLOEXEC
    auto sock = socket(family_inner, type_inner | SOCK_CLOEXEC, 0);
#else
    auto sock = socket(family, type, 0);
#endif
#endif

    if (sock != INVALID_SOCKET) {
        return Socket { sock };
    }

#if !defined(_WIN32) & !defined(SOCK_CLOEXEC)
    if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) {
        return tl::make_unexpected(get_last_error());
    }

#ifdef __APPLE__
    ::setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, 1);
#endif
#endif

    if (const auto err = get_last_error().value();
#ifdef _WIN32
        err != WSAEPROTOTYPE && err != WSAEINVAL) {
#else
        err != EPROTOTYPE && err != EINVAL) {
#endif
        return tl::make_unexpected(get_last_error());
    }

// Try again without SOCK_CLOEXEC.
#ifdef _WIN32
    sock = WSASocketW(
        family_inner, type_inner, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);
#else
    sock = socket(family_inner, type_inner, 0);
#endif

    if (sock != INVALID_SOCKET) {
        return Socket { sock };
    }

    return tl::make_unexpected(get_last_error());
}

Result<std::pair<Socket, SocketAddr>> Socket::accept() const
{
    sockaddr_storage addr {};
    socklen_t len = sizeof(addr);

    const auto sock
        = ::accept(as_raw_socket(), reinterpret_cast<sockaddr*>(&addr), &len);

    if (sock == INVALID_SOCKET) {
        return tl::make_unexpected(get_last_error());
    }

    const auto result = sockaddr_to_addr(addr, len);

    if (!result) {
        return tl::make_unexpected(result.error());
    }

    return std::make_pair(Socket { sock }, *result);
}

Result<size_t> Socket::recv_with_flags(
    tcb::span<std::byte> buf, int flags) const
{
    const auto len = (std::min)(buf.size(), MAX_READ_SIZE);

#ifdef _WIN32
    using recv_t = int;
#else
    using recv_t = size_t;
#endif

    const auto result = ::recv(as_raw_socket(),
        reinterpret_cast<char*>(buf.data()), static_cast<recv_t>(len), flags);

    if (result == -1) {
        const auto err = get_last_error();

#ifdef _WIN32
        if (err.value() == WSAESHUTDOWN) {
            return {};
        }
#endif

        return tl::make_unexpected(err);
    }

    return static_cast<size_t>(result);
}

Result<size_t> Socket::peek(tcb::span<std::byte> buf) const
{
    return recv_with_flags(buf, MSG_PEEK);
}

Result<std::pair<size_t, SocketAddr>> Socket::recv_from_with_flags(
    tcb::span<std::byte> buf, int flags) const
{
    sockaddr_storage storage {};
    socklen_t addrlen = sizeof(storage);

    const auto len = static_cast<int>((std::min)(
        buf.size(), static_cast<size_t>((std::numeric_limits<int>::max)())));

#ifdef _WIN32
    using recv_t = int;
#else
    using recv_t = size_t;
#endif

    const auto result = ::recvfrom(as_raw_socket(),
        reinterpret_cast<char*>(buf.data()), static_cast<recv_t>(len), flags,
        reinterpret_cast<sockaddr*>(&storage), &addrlen);

    const auto addr = sockaddr_to_addr(storage, static_cast<size_t>(addrlen));

    if (!addr) {
        return tl::make_unexpected(addr.error());
    }

    if (result == -1) {
        const auto err = get_last_error();

#ifdef _WIN32
        if (err.value() == WSAESHUTDOWN) {
#else
        if (err.value() == ESHUTDOWN) {
#endif
            return std::make_pair(0, *addr);
        }

        return tl::make_unexpected(err);
    }

    return std::make_pair(static_cast<size_t>(result), *addr);
}

Result<std::pair<size_t, SocketAddr>> Socket::peek_from(
    tcb::span<std::byte> buf) const
{
    return recv_from_with_flags(buf, MSG_PEEK);
}

Result<size_t> Socket::send(tcb::span<const std::byte> buf) const
{
    const auto len = static_cast<int>((std::min)(buf.size(), MAX_READ_SIZE));

#ifdef _WIN32
    using send_t = int;
#else
    using send_t = size_t;
#endif

    const auto sent
        = ::send(as_raw_socket(), reinterpret_cast<const char*>(buf.data()),
            static_cast<send_t>(len), MSG_NOSIGNAL);

    if (sent == -1) {
        return tl::make_unexpected(get_last_error());
    }

    return static_cast<size_t>(sent);
}

Result<void> Socket::shutdown(Shutdown how) const
{
    const auto h = [how]() -> int {
        switch (how) {
        case Shutdown::Read:
#ifdef _WIN32
            return SD_RECEIVE;
#else
            return SHUT_RD;
#endif
        case Shutdown::Write:
#ifdef _WIN32
            return SD_SEND;
#else
            return SHUT_WR;
#endif
        case Shutdown::Both:
#ifdef _WIN32
            return SD_BOTH;
#else
            return SHUT_RDWR;
#endif
        }

        return 0;
    }();

    if (::shutdown(as_raw_socket(), h) == -1) {
        return tl::make_unexpected(get_last_error());
    }

    return {};
}

Result<void> Socket::set_nonblocking(bool nonblocking) const
{
#ifdef _WIN32
    u_long mode = nonblocking ? 1 : 0;

    if (ioctlsocket(as_raw_socket(), FIONBIO, &mode) == SOCKET_ERROR) {
        return tl::make_unexpected(get_last_error());
    }
#else
    const auto flags = fcntl(as_raw_socket(), F_GETFL, 0);

    if (flags == -1) {
        return tl::make_unexpected(get_last_error());
    }

    if (fcntl(as_raw_socket(), F_SETFL,
            nonblocking ? flags | O_NONBLOCK : flags & ~O_NONBLOCK)
        == -1) {
        return tl::make_unexpected(get_last_error());
    }
#endif

    return {};
}

Result<void> Socket::set_broadcast(bool broadcast) const
{
    const auto b = broadcast ? 1 : 0;

    if (::setsockopt(as_raw_socket(), SOL_SOCKET, SO_BROADCAST,
            reinterpret_cast<const char*>(&b), sizeof(b))
        == -1) {
        return tl::make_unexpected(get_last_error());
    }

    return {};
}

Result<void> Socket::poll(int timeout_ms, PollEvent want) const
{
    if ((timeout_ms != -1 && timeout_ms < 0)
        || (want != PollEvent::Read && want != PollEvent::Write
            && want != PollEvent::Both)) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    if (!is_valid()) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::bad_file_descriptor));
    }

    pollfd pfd {};
    pfd.fd = as_raw_socket();
    pfd.events = [want]() -> short {
        switch (want) {
        case PollEvent::Read:
            return POLLIN;
        case PollEvent::Write:
            return POLLOUT;
        case PollEvent::Both:
            return POLLIN | POLLOUT;
        }

        return 0;
    }();

    const auto result = SYS_POLL(&pfd, 1, timeout_ms);

    if (result == -1) {
        return tl::make_unexpected(get_last_error());
    }

    if (result == 0) {
        return tl::make_unexpected(std::make_error_code(std::errc::timed_out));
    }

    if ((pfd.revents & POLLERR) != 0) {
        return tl::make_unexpected(get_last_error());
    }

    if ((pfd.revents & POLLHUP) != 0) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::connection_aborted));
    }

    if ((pfd.revents & POLLNVAL) != 0) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::bad_file_descriptor));
    }

    if (((static_cast<uint8_t>(want) & static_cast<uint8_t>(PollEvent::Read))
            != 0)
        && ((pfd.revents & POLLIN) == 0)) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::operation_would_block));
    }

    if (((static_cast<uint8_t>(want) & static_cast<uint8_t>(PollEvent::Write))
            != 0)
        && ((pfd.revents & POLLOUT) == 0)) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::operation_would_block));
    }

    return {};
}
} // namespace net
