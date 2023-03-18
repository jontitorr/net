#pragma once
#include <net/socket.hpp>

namespace net {
struct NET_EXPORT UdpSocket {
    static Result<UdpSocket> bind(SocketAddr addr);

    [[nodiscard]] const Socket& socket() const { return m_inner; }

    [[nodiscard]] RawSocket as_raw_socket() const
    {
        return m_inner.as_raw_socket();
    }

    [[nodiscard]] Result<SocketAddr> peer_addr() const;
    [[nodiscard]] Result<SocketAddr> socket_addr() const;

    [[nodiscard]] Result<std::pair<size_t, SocketAddr>> recv_from(
        tcb::span<std::byte> buf) const
    {
        return m_inner.recv_from(buf);
    }

    [[nodiscard]] Result<std::pair<size_t, SocketAddr>> peek_from(
        tcb::span<std::byte> buf) const
    {
        return m_inner.peek_from(buf);
    }

    [[nodiscard]] Result<size_t> send_to(
        tcb::span<const std::byte> buf, SocketAddr addr) const;

    [[nodiscard]] Result<void> set_nonblocking(bool nonblocking) const
    {
        return m_inner.set_nonblocking(nonblocking);
    }

    [[nodiscard]] Result<void> set_broadcast(bool broadcast) const
    {
        return m_inner.set_broadcast(broadcast);
    }

    [[nodiscard]] Result<size_t> recv(tcb::span<std::byte> buf) const
    {
        return m_inner.recv(buf);
    }

    [[nodiscard]] Result<size_t> peek(tcb::span<std::byte> buf) const
    {
        return m_inner.peek(buf);
    }

    [[nodiscard]] Result<size_t> send(tcb::span<const std::byte> buf) const
    {
        return m_inner.send(buf);
    }

    [[nodiscard]] Result<size_t> read(tcb::span<std::byte> buf) const
    {
        return recv(buf);
    }

    [[nodiscard]] Result<size_t> write(tcb::span<const std::byte> buf) const
    {
        return send(buf);
    }

    [[nodiscard]] Result<void> connect(SocketAddr addr) const;
    [[nodiscard]] Result<void> flush() const { return {}; }

private:
    explicit UdpSocket(Socket inner)
        : m_inner { std::move(inner) }
    {
    }

    Socket m_inner;
};
} // namespace net
