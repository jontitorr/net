#pragma once
#include <net/socket_addr.hpp>
#include <tcb/span.hpp>

namespace net {
#ifdef _WIN32
#ifdef _WIN64
using RawSocket = uint64_t;
#else
using RawSocket = uint32_t;
#endif
static constexpr RawSocket INVALID_SOCKET = ~RawSocket {};
#else
using RawSocket = int;

static constexpr RawSocket INVALID_SOCKET = -1;
#endif

struct NET_EXPORT Socket {
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&&) noexcept;
    Socket& operator=(Socket&&) noexcept;
    ~Socket();

    enum class Domain : uint8_t {
        Ipv4,
        Ipv6,
    };

    enum class Type : uint8_t {
        Stream,
        Dgram,
        SeqPacket,
        Raw,
    };

    static Result<Socket> create(SocketAddr addr, Type type);
    static Result<Socket> create_raw(Domain family, Type type);

    [[nodiscard]] RawSocket as_raw_socket() const { return m_socket; }
    [[nodiscard]] bool is_valid() const { return m_socket != INVALID_SOCKET; }

    [[nodiscard]] Result<std::pair<Socket, SocketAddr>> accept() const;
    [[nodiscard]] Result<size_t> recv_with_flags(
        tcb::span<std::byte> buf, int flags) const;

    [[nodiscard]] Result<size_t> recv(tcb::span<std::byte> buf) const
    {
        return recv_with_flags(buf, 0);
    }

    [[nodiscard]] Result<size_t> read(tcb::span<std::byte> buf) const
    {
        return recv(buf);
    }

    [[nodiscard]] Result<size_t> peek(tcb::span<std::byte> buf) const;
    [[nodiscard]] Result<std::pair<size_t, SocketAddr>> recv_from_with_flags(
        tcb::span<std::byte> buf, int flags) const;

    [[nodiscard]] Result<std::pair<size_t, SocketAddr>> recv_from(
        tcb::span<std::byte> buf) const
    {
        return recv_from_with_flags(buf, 0);
    }

    [[nodiscard]] Result<std::pair<size_t, SocketAddr>> peek_from(
        tcb::span<std::byte> buf) const;

    [[nodiscard]] Result<size_t> send(tcb::span<const std::byte> buf) const;

    [[nodiscard]] Result<size_t> write(tcb::span<const std::byte> buf) const
    {
        return send(buf);
    }

    enum class Shutdown : uint8_t { Read, Write, Both };

    [[nodiscard]] Result<void> shutdown(Shutdown how) const;
    [[nodiscard]] Result<void> set_nonblocking(bool nonblocking) const;
    [[nodiscard]] Result<void> set_broadcast(bool broadcast) const;

    // Create tiny class that wraps around an int for specifying the timeout for
    // polling which contains a constant for infinite timeout.

    struct PollTimeout {
        static constexpr int Infinite { -1 };
    };

    enum class PollEvent : uint8_t { Read, Write, Both };

    [[nodiscard]] Result<void> poll(int timeout_ms, PollEvent want) const;

private:
    explicit Socket(RawSocket sock)
        : m_socket { sock }
    {
    }

    RawSocket m_socket = INVALID_SOCKET;
};
} // namespace net
