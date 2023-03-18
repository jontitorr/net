#include <cstring>
#include <iomanip>
#include <limits>
#include <net/ip_addr.hpp>
#include <numeric>
#include <sstream>
#include <string>

namespace {
// From: https://stackoverflow.com/a/31697222
net::Result<std::array<std::byte, 4>> parse_ipv4_addr(std::string_view ipv4_str)
{
    std::array<std::byte, 4> result {};
    uint32_t octet_accumulator {};
    uint8_t dot_count {};
    uint8_t octet_index {};

    auto current_char = ipv4_str.begin();

    while (current_char != ipv4_str.end()) {
        result.at(octet_index) = {};
        octet_accumulator = 0;

        while (current_char != ipv4_str.end()
            && ((*current_char == ' ') || (*current_char == '\t'))) {
            current_char++;
        }

        while (current_char != ipv4_str.end()) {
            if ((*current_char == ' ') || (*current_char == '\t')) {
                while (current_char != ipv4_str.end()
                    && ((*current_char == ' ') || (*current_char == '\t'))) {
                    current_char++;
                }

                if (*current_char != '.') {
                    break;
                }
            }

            if (*current_char == '.') {
                dot_count++;
                current_char++;
                break;
            }

            if ((*current_char >= '0') && (*current_char <= '9')) {
                octet_accumulator *= 10;
                octet_accumulator += static_cast<uint32_t>(*current_char - '0');
                current_char++;
            }
        }

        if ((octet_accumulator > (std::numeric_limits<uint8_t>::max)())
            || (current_char != ipv4_str.end() && *current_char == '.')) {
            return tl::unexpected { std::make_error_code(
                std::errc::invalid_argument) };
        }

        result.at(octet_index) = static_cast<std::byte>(octet_accumulator);
        octet_index++;
    }

    if ((octet_index == 4) && (dot_count == 3)) {
        return result;
    }

    return tl::unexpected { std::make_error_code(std::errc::invalid_argument) };
}

int8_t ascii_to_hex(char c)
{
    c |= 0x20;

    if (c >= '0' && c <= '9') {
        return static_cast<int8_t>(c - '0');
    }

    if (c >= 'a' && c <= 'f') {
        return static_cast<int8_t>((c - 'a') + 10);
    }

    return -1;
}

constexpr uint8_t MAX_IPV6_ADDRESS_STR_LEN = 39;

// From https://gist.github.com/njh/84125c8ededdeb74ec5cc80a4003f308
net::Result<std::array<std::byte, 16>> parse_ipv6_addr(
    std::string_view ipv6_str)
{
    uint16_t accumulator {};
    size_t colon_count {};
    size_t pos {};
    std::array<std::byte, 16> result {};

    // Step 1: look for position of ::, and count colons after it
    for (size_t i { 1 }; i <= MAX_IPV6_ADDRESS_STR_LEN && i < ipv6_str.size();
         ++i) {
        if (ipv6_str.at(i) == ':') {
            if (ipv6_str.at(i - 1) == ':') {
                // Double colon!
                colon_count = 14;
            } else if (colon_count != 0) {
                // Count backwards the number of colons after the ::
                colon_count -= 2;
            }
        } else if (ipv6_str.at(i) == '\0') {
            break;
        }
    }

    // Step 2: convert from ascii to binary
    for (size_t i {};
         i <= MAX_IPV6_ADDRESS_STR_LEN && i < ipv6_str.size() && pos < 16;
         ++i) {
        if (ipv6_str.at(i) == ':' || ipv6_str.at(i) == '\0') {
            result.at(pos) = static_cast<std::byte>(accumulator >> 8);
            result.at(pos + 1) = static_cast<std::byte>(accumulator & 0xff);
            accumulator = 0;

            if ((colon_count != 0) && (i != 0) && ipv6_str.at(i - 1) == ':') {
                pos = colon_count;
            } else {
                pos += 2;
            }
        } else {
            const auto val = ascii_to_hex(ipv6_str.at(i));

            if (val == -1) {
                // Not hex or colon: fail
                return tl::unexpected { std::make_error_code(
                    std::errc::invalid_argument) };
            }

            accumulator = static_cast<uint16_t>(accumulator << 4);
            accumulator |= static_cast<uint16_t>(val);
        }

        if (ipv6_str.at(i) == '\0') {
            break;
        }
    }

    // Success
    return result;
}

constexpr std::array<char, 16> HEX_CHARS { '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

constexpr std::array<char, 2> get_padded_hex(uint8_t byte)
{
    return { HEX_CHARS.at((byte >> 4) & 0x0f), HEX_CHARS.at(byte & 0x0f) };
}
} // namespace

namespace net {
Result<Ipv4Addr> Ipv4Addr::parse(std::string_view str)
{
    const auto octets = parse_ipv4_addr(str);

    if (!octets) {
        return tl::make_unexpected(octets.error());
    }

    return Ipv4Addr { *octets };
}

std::string Ipv4Addr::to_string() const
{
    return std::accumulate(std::next(m_octets.begin()), m_octets.end(),
        std::to_string(static_cast<uint8_t>(m_octets.front())),
        [](const std::string& str, std::byte octet) {
            return str + "." + std::to_string(static_cast<uint8_t>(octet));
        });
}

Result<Ipv6Addr> Ipv6Addr::parse(std::string_view str)
{
    const auto octets = parse_ipv6_addr(str);

    if (!octets) {
        return tl::make_unexpected(octets.error());
    }

    return Ipv6Addr { *octets };
}

std::string Ipv6Addr::to_string() const
{
    std::string ret;

    for (size_t i {}; i < 16; ++i) {
        const auto hex = get_padded_hex(static_cast<uint8_t>(m_octets.at(i)));
        ret += std::string_view { hex.data(), hex.size() };

        if (i % 2 == 1 && i < 15) {
            ret += ':';
        }
    }

    return ret;
}
} // namespace net
