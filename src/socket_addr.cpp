#include <net/socket_addr.hpp>
#include <numeric>
#include <string>

namespace {
net::Result<net::SocketAddrV4> parse_socket_addrv4(std::string_view str)
{
    const auto colon = str.find(':');

    if (colon == std::string_view::npos) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    const auto addr_str = str.substr(0, colon);
    const auto port_str = str.substr(colon + 1);

    const auto addr = net::Ipv4Addr::parse(addr_str);

    if (!addr) {
        return tl::make_unexpected(addr.error());
    }

    const auto port = std::stoul(std::string { port_str });

    if (port > (std::numeric_limits<uint16_t>::max)()) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    return net::SocketAddrV4::create(*addr, static_cast<uint16_t>(port));
}

net::Result<net::SocketAddrV6> parse_socket_addrv6(std::string_view str)
{
    if (!str.starts_with('[')) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    const auto ending_bracket = str.find(']');

    if (ending_bracket == std::string_view::npos) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    const auto colon = str.find(':', ending_bracket);

    if (colon == std::string_view::npos) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    const auto addr_str = str.substr(1, ending_bracket - 1);
    const auto port_str = str.substr(colon + 1);

    const auto addr = net::Ipv6Addr::parse(addr_str);

    if (!addr) {
        return tl::make_unexpected(addr.error());
    }

    const auto port = std::stoul(std::string { port_str });

    if (port > (std::numeric_limits<uint16_t>::max)()) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    return net::SocketAddrV6::create(*addr, static_cast<uint16_t>(port));
}
} // namespace

namespace net {
SocketAddrV4 SocketAddrV4::create(Ipv4Addr addr, uint16_t port)
{
    return SocketAddrV4 { addr, port };
}

Result<SocketAddrV4> SocketAddrV4::parse(std::string_view str)
{
    return parse_socket_addrv4(str);
}

SocketAddrV6 SocketAddrV6::create(Ipv6Addr addr, uint16_t port)
{
    return SocketAddrV6 { addr, port };
}

Result<SocketAddrV6> SocketAddrV6::parse(std::string_view str)
{
    return parse_socket_addrv6(str);
}

Result<SocketAddr> SocketAddr::parse(std::string_view str)
{
    if (auto addrv6 = parse_socket_addrv6(str); addrv6) {
        return SocketAddr { *addrv6 };
    }

    if (auto addrv4 = parse_socket_addrv4(str); addrv4) {
        return SocketAddr { *addrv4 };
    }

    return tl::make_unexpected(
        std::make_error_code(std::errc::invalid_argument));
}

std::string SocketAddr::to_string() const
{
    return std::visit(
        [](const auto& addr) { return addr.to_string(); }, m_addr);
}
} // namespace net
