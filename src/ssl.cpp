#include <cassert>
#include <cstring>
#include <net/ssl.hpp>
#include <numeric>

#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wuseless-cast"
#endif
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#ifndef _WIN32
#pragma GCC diagnostic pop
#endif

#ifdef _WIN32
#define NOMINMAX
#include <WS2tcpip.h>
#include <WinSock2.h>

using in_port_t = u_short;
#else
#include <arpa/inet.h>
#endif

namespace {
std::error_code get_openssl_error()
{
    // TODO: Make this function actually return a useful error code.

    const auto error = ERR_get_error();

    if (error == 0) {
        return {};
    }

    return std::error_code { static_cast<int>(error), std::system_category() };
}

void init()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(
        OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
        nullptr);
#endif
}

using net::Result;
using net::SslError;
using net::SslMethod;

using UniqueBIO
    = std::unique_ptr<BIO, decltype([](BIO* bio) { BIO_free(bio); })>;

using UniqueBIO_ADDR = std::unique_ptr<BIO_ADDR,
    decltype([](BIO_ADDR* addr) { BIO_ADDR_free(addr); })>;

using UniqueBIO_METHOD = std::unique_ptr<BIO_METHOD,
    decltype([](BIO_METHOD* method) { BIO_meth_free(method); })>;

using UniqueSSL
    = std::unique_ptr<SSL, decltype([](SSL* ssl) { SSL_free(ssl); })>;

constexpr int COOKIE_SECRET_LENGTH { 16 };
const std::array<unsigned char, COOKIE_SECRET_LENGTH>& cookie_secret()
{
    static const auto ret = [] {
        std::array<unsigned char, COOKIE_SECRET_LENGTH> secret {};
        RAND_bytes(secret.data(), static_cast<int>(secret.size()));
        return secret;
    }();
    return ret;
}

int vs_dtls_generate_cookie(
    SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> result {};
    unsigned int length = 0;
    unsigned int result_length;
    union {
        sockaddr_storage storage;
        sockaddr_in ip4;
        sockaddr_in6 ip6;
    } peer;

    /* Read peer information */
#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
    if (const auto ret = BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
        ret < 1) {
        return 0;
    }
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif

    /* Create buffer with peer's address and port */
    length = 0;

    if (peer.storage.ss_family == AF_INET6) {
        length += sizeof(in6_addr);
    } else if (peer.storage.ss_family == AF_INET) {
        length += sizeof(in_addr);
    }

    length += sizeof(in_port_t);
    auto* buffer = reinterpret_cast<unsigned char*>(OPENSSL_malloc(length));

    if (buffer == nullptr) {
        return 0;
    }

    if (peer.storage.ss_family == AF_INET6) {
        memcpy(buffer, &peer.ip6.sin6_port, sizeof(in_port_t));
        memcpy(
            buffer + sizeof(in_port_t), &peer.ip6.sin6_addr, sizeof(in6_addr));
    } else if (peer.storage.ss_family == AF_INET) {
        memcpy(buffer, &peer.ip4.sin_port, sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t), &peer.ip4.sin_addr, sizeof(in_addr));
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), reinterpret_cast<const void*>(cookie_secret().data()),
        COOKIE_SECRET_LENGTH, reinterpret_cast<const unsigned char*>(buffer),
        length, result.data(), &result_length);
    OPENSSL_free(buffer);

    memcpy(cookie, result.data(), result_length);
    *cookie_len = result_length;

    return 1;
}

int vs_dtls_verify_cookie(
    SSL* ssl, const unsigned char* cookie, unsigned int cookie_len)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> result {};
    union {
        sockaddr_storage storage;
        sockaddr_in ip4;
        sockaddr_in6 ip6;
    } peer;

/* Read peer information */
#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
    const auto ret = BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif

    if (ret < 1) {
        return 0;
    }

    const auto length = [&peer] {
        if (peer.storage.ss_family == AF_INET) {
            return sizeof(in_addr) + sizeof(in_port_t);
        }
        if (peer.storage.ss_family == AF_INET6) {
            return sizeof(in6_addr) + sizeof(in_port_t);
        }
        return sizeof(in_port_t);
    }();

    /* Create buffer with peer's address and port */
    auto* buffer = static_cast<unsigned char*>(OPENSSL_malloc(length));

    if (buffer == nullptr) {
        return 0;
    }

    if (peer.storage.ss_family == AF_INET) {
        memcpy(buffer, &peer.ip4.sin_port, sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t), &peer.ip4.sin_addr, sizeof(in_addr));
    } else if (peer.storage.ss_family == AF_INET6) {
        memcpy(buffer, &peer.ip6.sin6_port, sizeof(in_port_t));
        memcpy(
            buffer + sizeof(in_port_t), &peer.ip6.sin6_addr, sizeof(in6_addr));
    }

    unsigned int result_length;

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), reinterpret_cast<const void*>(cookie_secret().data()),
        COOKIE_SECRET_LENGTH, reinterpret_cast<const unsigned char*>(buffer),
        length, result.data(), &result_length);
    OPENSSL_free(buffer);

    return cookie_len == result_length
            && std::equal(result.begin(), result.end(), cookie)
        ? 1
        : 0;
}

struct SslContext {
    static Result<SslContext> create(SslMethod method)
    {
        init();

        auto* ctx = [method] {
            switch (method) {
                using enum net::SslMethod;
            case Tls:
                return SSL_CTX_new(TLS_method());
            case TlsClient:
                return SSL_CTX_new(TLS_client_method());
            case TlsServer:
                return SSL_CTX_new(TLS_server_method());
            case Dtls:
                return SSL_CTX_new(DTLS_method());
            case DtlsClient:
                return SSL_CTX_new(DTLS_client_method());
            case DtlsServer:
                return SSL_CTX_new(DTLS_server_method());
            default:
                return static_cast<SSL_CTX*>(nullptr);
            }
        }();

        // If our method is DTLS, we need to set cookie callbacks.
        if (method == SslMethod::Dtls || method == SslMethod::DtlsClient
            || method == SslMethod::DtlsServer) {
            SSL_CTX_set_cookie_generate_cb(ctx, vs_dtls_generate_cookie);
            SSL_CTX_set_cookie_verify_cb(ctx, vs_dtls_verify_cookie);
        }

        if (ctx == nullptr) {
            return tl::make_unexpected(get_openssl_error());
        }

        return SslContext { ctx };
    }

    [[nodiscard]] SSL_CTX* as_raw() const { return m_inner; }

private:
    explicit SslContext(SSL_CTX* ctx)
        : m_inner { ctx }
    {
    }

    SSL_CTX* m_inner;
};

using net::TcpStream;
using net::UdpSocket;

struct Ssl {
    template<net::Stream S> static Result<Ssl> create(
        const SslContext& ctx, const S& stream, bool is_client)
    {
        auto* s_bio = [&stream] {
            if constexpr (std::is_same_v<S, TcpStream>) {
                return [&stream]() -> BIO* {
                    static const auto* method = [] {
                        auto* ret = BIO_meth_new(BIO_TYPE_SOCKET, "net_socket");
                        static const auto send_no_pipe = [](BIO* b,
                                                             const char* buf,
                                                             int len) {

#ifdef _WIN32
                            using send_t = int;
                            static constexpr int
                                MSG_NOSIGNAL {}; // MSG_NOSIGNAL is not
                            // supported on Windows.
                            WSASetLastError(0);
#else
                            using send_t = size_t;
                            errno = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

                            const int sent = static_cast<int>(::send(
                                static_cast<int>(BIO_get_fd(b, nullptr)), buf,
                                static_cast<send_t>(len), MSG_NOSIGNAL));
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif

                            BIO_clear_retry_flags(b);

                            if (sent <= 0 && BIO_sock_should_retry(sent)) {
                                BIO_set_retry_write(b);
                            }

                            return sent;
                        };

                        BIO_meth_set_write(ret, send_no_pipe);
                        BIO_meth_set_read(
                            ret, BIO_meth_get_read(BIO_s_socket()));

                        BIO_meth_set_puts(ret, [](BIO* b, const char* str) {
                            return send_no_pipe(
                                b, str, static_cast<int>(std::strlen(str)));
                        });

                        BIO_meth_set_gets(
                            ret, BIO_meth_get_gets(BIO_s_socket()));
                        BIO_meth_set_ctrl(
                            ret, BIO_meth_get_ctrl(BIO_s_socket()));
                        BIO_meth_set_create(
                            ret, BIO_meth_get_create(BIO_s_socket()));
                        BIO_meth_set_destroy(
                            ret, BIO_meth_get_destroy(BIO_s_socket()));
                        BIO_meth_set_callback_ctrl(
                            ret, BIO_meth_get_callback_ctrl(BIO_s_socket()));

                        return ret;
                    }();

                    auto* ret = BIO_new(method);

                    if (ret == nullptr) {
                        return nullptr;
                    }

                    BIO_set_fd(ret, static_cast<int>(stream.as_raw_socket()),
                        BIO_NOCLOSE);

                    return ret;
                }();
            } else {
                return BIO_new_dgram(
                    static_cast<int>(stream.as_raw_socket()), BIO_NOCLOSE);
            }
        }();

        auto ssl = UniqueBIO { BIO_new_ssl(
            ctx.as_raw(), static_cast<int>(is_client)) };

        BIO_push(ssl.get(), s_bio);

        if (!ssl) {
            return tl::make_unexpected(get_openssl_error());
        }

        return Ssl { std::move(ssl) };
    }

    [[nodiscard]] BIO* as_raw() const { return m_ssl.get(); }

    [[nodiscard]] SSL* as_ssl() const
    {
        SSL* ssl;
#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
        BIO_get_ssl(m_ssl.get(), &ssl);
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif
        return ssl;
    }

    [[nodiscard]] SslError get_error(int ret) const
    {
        const auto err = SSL_get_error(as_ssl(), ret);

        switch (err) {
        case SSL_ERROR_NONE:
            return SslError::None;
        case SSL_ERROR_ZERO_RETURN:
            return SslError::ZeroReturn;
        case SSL_ERROR_WANT_READ:
            return SslError::WantRead;
        case SSL_ERROR_WANT_WRITE:
            return SslError::WantWrite;
        case SSL_ERROR_WANT_CONNECT:
            return SslError::WantConnect;
        case SSL_ERROR_WANT_ACCEPT:
            return SslError::WantAccept;
        case SSL_ERROR_WANT_X509_LOOKUP:
            return SslError::WantX509Lookup;
        case SSL_ERROR_SYSCALL:
            return SslError::Syscall;
        case SSL_ERROR_SSL:
            return SslError::Ssl;
        default:
            return SslError::Unknown;
        }
    }

    [[nodiscard]] net::Result<void> connect() const
    {
        return BIO_do_connect(m_ssl.get()) == 1
            ? net::Result<void> {}
            : tl::make_unexpected(get_openssl_error());
    }

private:
    explicit Ssl(UniqueBIO ssl)
        : m_ssl { std::move(ssl) }
    {
    }

    UniqueBIO m_ssl;
};

using net::Stream;

template<Stream S> struct StreamState {
    UniqueBIO bio; // Will utilize the stream/socket for I/O.
    S stream; // Held for lifetime management.
};

template<Stream S> inline StreamState<S>& state(BIO* bio)
{
    return *static_cast<StreamState<S>*>(BIO_get_data(bio));
}

template<typename T = void> Result<T> cvt_ssl(int ret, const Ssl& ssl)
{
    if (ret > 0) {
        if constexpr (std::is_same_v<T, void>) {
            return {};
        } else {
            return static_cast<T>(ret);
        }
    }

    const auto err = std::error_code { ssl.get_error(ret) };

    return tl::make_unexpected(err);
}
} // namespace

namespace net {
const std::error_category& ssl_error_category() noexcept
{
    static struct : std::error_category {
        [[nodiscard]] const char* name() const noexcept override
        {
            return "ssl";
        }

        [[nodiscard]] std::string message(int ev) const override
        {
            switch (static_cast<SslError>(ev)) {
                using enum net::SslError;
            case None:
                return "No error";
            case ZeroReturn:
                return "The TLS/SSL connection has been closed";
            case WantRead:
            case WantWrite:
            case WantConnect:
            case WantAccept:
                return "The operation did not complete; the same TLS/SSL I/O "
                       "function should be called again later";
            case WantX509Lookup:
                return "The operation did not complete because an application "
                       "callback set by SSL_CTX_set_client_cert_cb() has "
                       "asked to be called again. The TLS/SSL I/O function "
                       "should be called again later";
            case Syscall:
                return "Some I/O error occurred";
            case Ssl:
                return "A failure in the SSL library occurred, usually a "
                       "protocol error";
            case Unknown:
                return "Unknown error";
            }

            return "Unknown error";
        }
    } category;
    return category;
}

template<Stream S> struct SslStream<S>::Impl {
    explicit Impl(Ssl ssl, S stream)
        : m_stream { std::move(stream) }
        , m_ssl { std::move(ssl) }
    {
    }

    S m_stream;
    Ssl m_ssl;
};

template<Stream S> SslStream<S>::SslStream(SslStream&&) noexcept = default;
template<Stream S> SslStream<S>& SslStream<S>::operator=(SslStream&&) noexcept
    = default;
template<Stream S> SslStream<S>::~SslStream() = default;

template<Stream S> const Socket& SslStream<S>::socket() const
{
    return m_impl->m_stream.socket();
}

template<Stream S>
Result<size_t> SslStream<S>::read(std::span<std::byte> buf) const
{
    if (buf.empty()) {
        return {};
    }

    const auto len = static_cast<int>(std::min(
        buf.size(), static_cast<size_t>(std::numeric_limits<int>::max())));

    const auto ret = BIO_read(m_impl->m_ssl.as_raw(), buf.data(), len);

    if (ret <= 0) {
        if (BIO_should_retry(m_impl->m_ssl.as_raw())) {
            // For portability.
            return tl::make_unexpected(std::make_error_code(
                std::errc::resource_unavailable_try_again));
        }

        return tl::make_unexpected(m_impl->m_ssl.get_error(ret));
    }

    return static_cast<size_t>(ret);
}

template<Stream S>
Result<size_t> SslStream<S>::write(std::span<const std::byte> buf) const
{
    if (buf.empty()) {
        return {};
    }

    const auto len = static_cast<int>(std::min(
        buf.size(), static_cast<size_t>(std::numeric_limits<int>::max())));

    const auto ret = BIO_write(m_impl->m_ssl.as_raw(), buf.data(), len);

    if (ret <= 0) {
        if (BIO_should_retry(m_impl->m_ssl.as_raw())) {
            // For portability.
            return tl::make_unexpected(std::make_error_code(
                std::errc::resource_unavailable_try_again));
        }

        return tl::make_unexpected(m_impl->m_ssl.get_error(ret));
    }

#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-value"
#endif
    BIO_flush(m_impl->m_ssl.as_raw());
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif

    return static_cast<size_t>(ret);
}

template<Stream S> Result<void> SslStream<S>::accept() const
{
    return cvt_ssl(SSL_accept(m_impl->m_ssl.as_ssl()), m_impl->m_ssl);
}

template<Stream S> Result<void> SslStream<S>::connect() const
{
    while (true) {
        const auto ret = BIO_do_connect(m_impl->m_ssl.as_raw());

        if (ret > 0) {
            break;
        }

        if (BIO_should_retry(m_impl->m_ssl.as_raw())) {
            continue;
        }

        return tl::make_unexpected(
            m_impl->m_ssl.get_error(static_cast<int>(ret)));
    }

    return {};
}

template<Stream S> Result<void> SslStream<S>::shutdown() const
{
    while (true) {
        const auto ret
            = cvt_ssl(SSL_shutdown(m_impl->m_ssl.as_ssl()), m_impl->m_ssl);

        if (ret) {
            break;
        }

        if (ret.error() == SslError::WantRead
            || ret.error() == SslError::WantWrite) {
            continue;
        }

        return tl::make_unexpected(ret.error());
    }

    if constexpr (std::is_same_v<S, TcpStream>) {
        return m_impl->m_stream.shutdown(Socket::Shutdown::Both);
    } else {
        return {};
    }
}

template<Stream S>
Result<void> SslStream<S>::set_nonblocking(bool nonblocking) const
{
    return ::state<S>(SSL_get_rbio(m_impl->m_ssl.as_ssl()))
        .stream.set_nonblocking(nonblocking);
}

struct SslProvider::Impl {
    explicit Impl(SslContext ctx)
        : m_ctx { ctx }
    {
    }

    SslContext m_ctx;
};

SslProvider::SslProvider(SslProvider&&) noexcept = default;
SslProvider& SslProvider::operator=(SslProvider&&) noexcept = default;
SslProvider::~SslProvider() = default;

Result<SslProvider> SslProvider::create(SslMethod method)
{
    using enum net::SslMethod;

    if (method != Tls && method != TlsClient && method != TlsServer
        && method != Dtls && method != DtlsClient && method != DtlsServer) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    const auto ctx = SslContext::create(method);

    if (!ctx) {
        return tl::make_unexpected(ctx.error());
    }

    SslProvider acceptor;
    acceptor.m_impl = std::make_unique<Impl>(*ctx);

    return acceptor;
}

Result<void> SslProvider::set_certificate_file(
    const std::string& file, SslFileType type) const
{
    if (type != SslFileType::Pem && type != SslFileType::Asn1) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    if (type == SslFileType::Pem) {
        if (SSL_CTX_use_certificate_chain_file(
                m_impl->m_ctx.as_raw(), file.c_str())
            == 0) {
            return tl::make_unexpected(get_openssl_error());
        }
    } else {
        if (SSL_CTX_use_certificate_file(
                m_impl->m_ctx.as_raw(), file.c_str(), SSL_FILETYPE_ASN1)
            == 0) {
            return tl::make_unexpected(get_openssl_error());
        }
    }

    return {};
}

Result<void> SslProvider::set_certificate_chain_file(
    const std::string& file) const
{
    if (SSL_CTX_use_certificate_chain_file(m_impl->m_ctx.as_raw(), file.c_str())
        == 0) {
        return tl::make_unexpected(get_openssl_error());
    }

    return {};
}

Result<void> SslProvider::set_private_key_file(
    const std::string& file, SslFileType type) const
{
    if (type != SslFileType::Pem && type != SslFileType::Asn1) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    if (type == SslFileType::Pem) {
        if (SSL_CTX_use_PrivateKey_file(
                m_impl->m_ctx.as_raw(), file.c_str(), SSL_FILETYPE_PEM)
            == 0) {
            return tl::make_unexpected(get_openssl_error());
        }
    } else {
        if (SSL_CTX_use_PrivateKey_file(
                m_impl->m_ctx.as_raw(), file.c_str(), SSL_FILETYPE_ASN1)
            == 0) {
            return tl::make_unexpected(get_openssl_error());
        }
    }

    return {};
}

template<Stream S> Result<SslStream<S>> SslProvider::accept(S stream) const
{
    auto ssl = Ssl::create(m_impl->m_ctx, stream, false);

    if (!ssl) {
        return tl::make_unexpected(SslError::Ssl);
    }

    SslStream<S> ssl_stream { std::make_unique<typename SslStream<S>::Impl>(
        std::move(*ssl), std::move(stream)) };

    if constexpr (std::is_same_v<S, UdpSocket>) {
        UniqueBIO_ADDR addr { BIO_ADDR_new() };
        const auto& ssl_ref = ssl_stream.m_impl->m_ssl;

        auto ret = DTLSv1_listen(ssl_ref.as_ssl(), addr.get());

        while (ret <= 0) {
            const auto err = ssl_ref.get_error(ret);

            if (err == SslError::WantRead) {
                ret = DTLSv1_listen(ssl_ref.as_ssl(), addr.get());
                continue;
            }

            return tl::make_unexpected(err);
        }
    }

    if (const auto ret = ssl_stream.accept(); !ret) {
        return tl::make_unexpected(ret.error());
    }

    return ssl_stream;
}

template<Stream S> Result<SslStream<S>> SslProvider::connect(S stream) const
{
    auto ssl = Ssl::create(m_impl->m_ctx, stream, true);

    if (!ssl) {
        return tl::make_unexpected(SslError::Ssl);
    }

    SslStream<S> ssl_stream { std::make_unique<typename SslStream<S>::Impl>(
        std::move(*ssl), std::move(stream)) };

    if (const auto ret = ssl_stream.connect(); !ret) {
        return tl::make_unexpected(ret.error());
    }

    return ssl_stream;
}

template struct SslStream<TcpStream>;
template struct SslStream<UdpSocket>;

template NET_EXPORT Result<SslStream<TcpStream>> SslProvider::accept(
    TcpStream) const;
template NET_EXPORT Result<SslStream<UdpSocket>> SslProvider::accept(
    UdpSocket) const;
template NET_EXPORT Result<SslStream<TcpStream>> SslProvider::connect(
    TcpStream) const;
template NET_EXPORT Result<SslStream<UdpSocket>> SslProvider::connect(
    UdpSocket) const;
} // namespace net
