#pragma once
#include <array>
#include <cstddef>
#include <net/export.h>
#include <net/util.hpp>
#include <string_view>

namespace net {
struct NET_EXPORT Ipv4Addr {
    static Ipv4Addr create(std::array<std::byte, 4> octets)
    {
        return Ipv4Addr { octets };
    }

    static Result<Ipv4Addr> parse(std::string_view str);
    static Ipv4Addr unspecified() { return Ipv4Addr {}; }
    static Ipv4Addr localhost()
    {
        return Ipv4Addr { std::array<std::byte, 4> { { std::byte { 127 },
            std::byte { 0 }, std::byte { 0 }, std::byte { 1U } } } };
    }
    static Ipv4Addr broadcast()
    {
        return Ipv4Addr { std::array<std::byte, 4> { { std::byte { 255 },
            std::byte { 255 }, std::byte { 255 }, std::byte { 255 } } } };
    }

    [[nodiscard]] std::array<std::byte, 4> octets() const { return m_octets; }
    [[nodiscard]] std::string to_string() const;

    bool operator==(const Ipv4Addr& other) const
    {
        return m_octets == other.m_octets;
    }

private:
    Ipv4Addr() = default;
    explicit Ipv4Addr(std::array<std::byte, 4> octets)
        : m_octets { octets }
    {
    }

    std::array<std::byte, 4> m_octets {};
};

struct NET_EXPORT Ipv6Addr {
    static Ipv6Addr create(std::array<std::byte, 16> octets)
    {
        return Ipv6Addr { octets };
    }

    static Result<Ipv6Addr> parse(std::string_view str);
    static Ipv6Addr unspecified() { return Ipv6Addr {}; }
    static Ipv6Addr localhost()
    {
        return Ipv6Addr { std::array<std::byte, 16> { { std::byte { 0 },
            std::byte { 0 }, std::byte { 0 }, std::byte { 0 }, std::byte { 0 },
            std::byte { 0 }, std::byte { 0 }, std::byte { 0 }, std::byte { 0 },
            std::byte { 0 }, std::byte { 0 }, std::byte { 0 }, std::byte { 0 },
            std::byte { 0 }, std::byte { 0 }, std::byte { 1U } } } };
    }

    [[nodiscard]] std::array<std::byte, 16> octets() const { return m_octets; }
    [[nodiscard]] std::string to_string() const;

    bool operator==(const Ipv6Addr& other) const
    {
        return m_octets == other.m_octets;
    }

private:
    Ipv6Addr() = default;
    explicit Ipv6Addr(std::array<std::byte, 16> octets)
        : m_octets { octets }
    {
    }

    std::array<std::byte, 16> m_octets {};
};
} // namespace net
