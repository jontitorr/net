#pragma once
#include <cstdint>
#include <net/ip_addr.hpp>
#include <string>
#include <variant>

namespace net {
struct NET_EXPORT SocketAddrV4 {
    static SocketAddrV4 create(Ipv4Addr addr, uint16_t port);
    static Result<SocketAddrV4> parse(std::string_view str);

    [[nodiscard]] const Ipv4Addr& ip() const { return m_addr; }
    [[nodiscard]] uint16_t port() const { return m_port; }

    [[nodiscard]] std::string to_string() const
    {
        return std::string { m_addr.to_string() } + ":"
            + std::to_string(m_port);
    }

private:
    SocketAddrV4(Ipv4Addr addr, uint16_t port)
        : m_addr { addr }
        , m_port { port }
    {
    }

    Ipv4Addr m_addr;
    uint16_t m_port;
};

struct NET_EXPORT SocketAddrV6 {
    static SocketAddrV6 create(Ipv6Addr addr, uint16_t port);
    static Result<SocketAddrV6> parse(std::string_view str);

    [[nodiscard]] const Ipv6Addr& ip() const { return m_addr; }
    [[nodiscard]] uint16_t port() const { return m_port; }

    [[nodiscard]] std::string to_string() const
    {
        return std::string { m_addr.to_string() } + ":"
            + std::to_string(m_port);
    }

private:
    SocketAddrV6(Ipv6Addr addr, uint16_t port)
        : m_addr { addr }
        , m_port { port }
    {
    }

    Ipv6Addr m_addr;
    uint16_t m_port;
};

struct SocketAddr {
    NET_EXPORT SocketAddr(SocketAddrV4 addr)
        : m_addr { addr }
    {
    }

    NET_EXPORT SocketAddr(SocketAddrV6 addr)
        : m_addr { addr }
    {
    }

    NET_EXPORT static Result<SocketAddr> parse(std::string_view str);

    [[nodiscard]] NET_EXPORT bool is_ipv4() const
    {
        return std::holds_alternative<SocketAddrV4>(m_addr);
    }

    [[nodiscard]] NET_EXPORT bool is_ipv6() const
    {
        return std::holds_alternative<SocketAddrV6>(m_addr);
    }

    [[nodiscard]] NET_EXPORT const Ipv4Addr& ipv4() const
    {
        return std::get<SocketAddrV4>(m_addr).ip();
    }

    [[nodiscard]] NET_EXPORT const Ipv6Addr& ipv6() const
    {
        return std::get<SocketAddrV6>(m_addr).ip();
    }

    [[nodiscard]] NET_EXPORT uint16_t port() const
    {
        return std::visit([](const auto& addr) { return addr.port(); }, m_addr);
    }

    [[nodiscard]] NET_EXPORT std::string to_string() const;

private:
    std::variant<SocketAddrV4, SocketAddrV6> m_addr;
};
} // namespace net
