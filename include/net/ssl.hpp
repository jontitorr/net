#pragma once
#include <cstdint>
#include <memory>
#include <net/tcp.hpp>
#include <net/udp.hpp>
#include <ostream>

namespace net {
enum class SslError : uint8_t {
    None,
    ZeroReturn,
    WantRead,
    WantWrite,
    WantConnect,
    WantAccept,
    WantX509Lookup,
    Syscall,
    Ssl,
    Unknown,
};
} // namespace net

template<> struct std::is_error_code_enum<net::SslError> : std::true_type {};

namespace net {
const std::error_category& ssl_error_category() noexcept;
[[nodiscard]] inline std::error_code make_error_code(SslError error) noexcept
{
    return { static_cast<int>(error), ssl_error_category() };
}

// ostream operator for SslError.
inline std::ostream& operator<<(std::ostream& os, SslError error)
{
    switch (error) {
    case net::SslError::None:
        return os << "None";
    case net::SslError::ZeroReturn:
        return os << "ZeroReturn";
    case net::SslError::WantRead:
        return os << "WantRead";
    case net::SslError::WantWrite:
        return os << "WantWrite";
    case net::SslError::WantConnect:
        return os << "WantConnect";
    case net::SslError::WantAccept:
        return os << "WantAccept";
    case net::SslError::WantX509Lookup:
        return os << "WantX509Lookup";
    case net::SslError::Syscall:
        return os << "Syscall";
    case net::SslError::Ssl:
        return os << "Ssl";
    case net::SslError::Unknown:
        return os << "Unknown";
    default:
        return os << "Invalid SslError value";
    }
}

enum class SslFileType : uint8_t {
    Pem,
    Asn1,
};

enum class SslMethod : uint8_t {
    Tls,
    TlsClient,
    TlsServer,
    Dtls,
    DtlsClient,
    DtlsServer
};

template<typename Stream> struct SslStream {
    static_assert(
        std::is_same_v<Stream, TcpStream> || std::is_same_v<Stream, UdpSocket>,
        "SslStream can only be used with TcpStream or UdpStream");

    SslStream(const SslStream&) = delete;
    SslStream& operator=(const SslStream&) = delete;
    NET_EXPORT SslStream(SslStream&&) noexcept;
    NET_EXPORT SslStream& operator=(SslStream&&) noexcept;
    NET_EXPORT ~SslStream();

    [[nodiscard]] NET_EXPORT const Socket& socket() const;

    [[nodiscard]] NET_EXPORT Result<size_t> read(
        tcb::span<std::byte> buf) const;
    [[nodiscard]] NET_EXPORT Result<size_t> write(
        tcb::span<const std::byte> buf) const;
    [[nodiscard]] NET_EXPORT Result<void> accept() const;
    [[nodiscard]] NET_EXPORT Result<void> connect() const;

    [[nodiscard]] NET_EXPORT Result<void> shutdown() const;
    [[nodiscard]] NET_EXPORT Result<void> set_nonblocking(
        bool nonblocking) const;

private:
    friend struct SslProvider;

    struct Impl;

    explicit SslStream(std::unique_ptr<Impl> impl)
        : m_impl { std::move(impl) }
    {
    }

    std::unique_ptr<Impl> m_impl;
};

struct SslProvider {
    SslProvider(const SslProvider&) = delete;
    SslProvider& operator=(const SslProvider&) = delete;
    NET_EXPORT SslProvider(SslProvider&&) noexcept;
    NET_EXPORT SslProvider& operator=(SslProvider&&) noexcept;
    NET_EXPORT ~SslProvider();

    NET_EXPORT static Result<SslProvider> create(SslMethod method);

    [[nodiscard]] NET_EXPORT SslProvider& set_sni(bool sni)
    {
        m_sni = sni;
        return *this;
    }

    [[nodiscard]] NET_EXPORT SslProvider& set_verify_hostname(
        bool verify_hostname)
    {
        m_verify_hostname = verify_hostname;
        return *this;
    }

    // TODO: Maybe split this into two separate classes for two different use
    // cases like client and server.

    [[nodiscard]] NET_EXPORT Result<void> set_certificate_file(
        const std::string& file, SslFileType type) const;
    [[nodiscard]] NET_EXPORT Result<void> set_certificate_chain_file(
        const std::string& file) const;
    [[nodiscard]] NET_EXPORT Result<void> set_private_key_file(
        const std::string& file, SslFileType type) const;

    template<typename Stream> [[nodiscard]] NET_EXPORT Result<SslStream<Stream>>
    accept(Stream stream) const;
    template<typename Stream> [[nodiscard]] NET_EXPORT Result<SslStream<Stream>>
    connect(std::optional<std::string_view> host, Stream stream) const;

private:
    SslProvider() = default;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
    bool m_sni { true };
    bool m_verify_hostname { true };
};
} // namespace net
