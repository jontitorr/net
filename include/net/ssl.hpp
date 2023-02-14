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
        using enum net::SslError;
    case None:
        return os << "None";
    case ZeroReturn:
        return os << "ZeroReturn";
    case WantRead:
        return os << "WantRead";
    case WantWrite:
        return os << "WantWrite";
    case WantConnect:
        return os << "WantConnect";
    case WantAccept:
        return os << "WantAccept";
    case WantX509Lookup:
        return os << "WantX509Lookup";
    case Syscall:
        return os << "Syscall";
    case Ssl:
        return os << "Ssl";
    case Unknown:
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

template<typename T>
concept Stream = std::is_same_v<T, TcpStream> || std::is_same_v<T, UdpSocket>;

template<Stream S> struct SslStream {
    SslStream(const SslStream&) = delete;
    SslStream& operator=(const SslStream&) = delete;
    NET_EXPORT SslStream(SslStream&&) noexcept;
    NET_EXPORT SslStream& operator=(SslStream&&) noexcept;
    NET_EXPORT ~SslStream();

    [[nodiscard]] NET_EXPORT const Socket& socket() const;

    [[nodiscard]] NET_EXPORT Result<size_t> read(
        std::span<std::byte> buf) const;
    [[nodiscard]] NET_EXPORT Result<size_t> write(
        std::span<const std::byte> buf) const;
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

    [[nodiscard]] NET_EXPORT Result<void> set_certificate_file(
        const std::string& file, SslFileType type) const;
    [[nodiscard]] NET_EXPORT Result<void> set_certificate_chain_file(
        const std::string& file) const;
    [[nodiscard]] NET_EXPORT Result<void> set_private_key_file(
        const std::string& file, SslFileType type) const;

    template<Stream S>
    [[nodiscard]] NET_EXPORT Result<SslStream<S>> accept(S stream) const;
    template<Stream S>
    [[nodiscard]] NET_EXPORT Result<SslStream<S>> connect(S stream) const;

private:
    SslProvider() = default;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
} // namespace net
