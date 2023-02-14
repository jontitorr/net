#pragma once
#include <map>
#include <net/ssl.hpp>
#include <net/tcp.hpp>
#include <net/uri.hpp>

namespace net {
using HttpHeaders = CaseInsensitiveMap;

enum class HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Connect,
    Trace,
    Patch,
};

[[nodiscard]] constexpr std::string_view method_name(HttpMethod method);

struct HttpRequest {
    HttpMethod method;
    std::string path;
    std::string body;
    HttpHeaders headers;
};

enum class HttpStatus : uint16_t {
    Continue = 100,
    SwitchingProtocols = 101,
    Processing = 102,
    EarlyHints = 103,
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoritativeInformation = 203,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    MultiStatus = 207,
    AlreadyReported = 208,
    IMUsed = 226,
    MultipleChoices = 300,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    UseProxy = 305,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,
    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    PayloadTooLarge = 413,
    URITooLong = 414,
    UnsupportedMediaType = 415,
    RangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    ImATeapot = 418,
    MisdirectedRequest = 421,
    UnprocessableEntity = 422,
    Locked = 423,
    FailedDependency = 424,
    TooEarly = 425,
    UpgradeRequired = 426,
    PreconditionRequired = 428,
    TooManyRequests = 429,
    RequestHeaderFieldsTooLarge = 431,
    UnavailableForLegalReasons = 451,
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HTTPVersionNotSupported = 505,
    VariantAlsoNegotiates = 506,
    InsufficientStorage = 507,
    LoopDetected = 508,
    NotExtended = 510,
    NetworkAuthenticationRequired = 511,
};

struct HttpResponse {
    HttpStatus status_code;
    std::string status_message;
    std::string body;
    HttpHeaders headers;
};

struct HttpConnection {
    [[nodiscard]] NET_EXPORT static Result<HttpConnection> connect(
        std::string_view url);
    [[nodiscard]] NET_EXPORT static Result<HttpResponse> send_request(
        std::string_view url, const HttpRequest& req);

    [[nodiscard]] NET_EXPORT const
        std::variant<TcpStream, SslStream<TcpStream>>&
        stream() const
    {
        return m_inner;
    }

    // FIXME: Remove as this should be part of another layer.
    [[nodiscard]] NET_EXPORT Result<void> respond(
        const HttpResponse& res) const;

    [[nodiscard]] NET_EXPORT Result<HttpResponse> request(
        const HttpRequest& req) const;

    NET_EXPORT void disconnect() const
    {
        return std::visit(
            []<typename Stream>(const Stream& stream) {
                if constexpr (std::is_same_v<Stream, TcpStream>) {
                    (void)stream.shutdown(Socket::Shutdown::Both);
                } else {
                    (void)stream.shutdown();
                }
            },
            m_inner);
    }

private:
    friend struct HttpServer;

    [[nodiscard]] RawSocket as_raw_socket() const
    {
        return std::visit(
            []<typename Stream>(const Stream& stream) {
                if constexpr (std::is_same_v<Stream, TcpStream>) {
                    return stream.as_raw_socket();
                } else {
                    return stream.socket().as_raw_socket();
                }
            },
            m_inner);
    }

    explicit HttpConnection(std::variant<TcpStream, SslStream<TcpStream>> inner,
        std::string_view host)
        : m_inner { std::move(inner) }
        , m_base_url { host }
    {
    }

    std::variant<TcpStream, SslStream<TcpStream>> m_inner;
    std::string m_base_url;
};

namespace http {
[[nodiscard]] NET_EXPORT Result<HttpResponse> get(std::string_view url);
[[nodiscard]] NET_EXPORT Result<HttpResponse> get(
    std::string_view url, const HttpHeaders& headers);
[[nodiscard]] NET_EXPORT Result<HttpResponse> post(
    std::string_view url, const std::string& body);
[[nodiscard]] NET_EXPORT Result<HttpResponse> put(
    std::string_view url, const std::string& body);
[[nodiscard]] NET_EXPORT Result<HttpResponse> del(std::string_view url);
[[nodiscard]] NET_EXPORT Result<HttpResponse> head(std::string_view url);
[[nodiscard]] NET_EXPORT Result<HttpResponse> options(std::string_view url);
[[nodiscard]] NET_EXPORT Result<HttpResponse> connect(std::string_view url);
[[nodiscard]] NET_EXPORT Result<HttpResponse> trace(std::string_view url);
[[nodiscard]] NET_EXPORT Result<HttpResponse> patch(
    std::string_view url, std::string_view body);

[[nodiscard]] NET_EXPORT constexpr std::string_view status_message(
    HttpStatus status);
} // namespace http

struct HttpServer {
    using RouteHandler = std::function<HttpResponse(const HttpRequest&)>;

    [[nodiscard]] NET_EXPORT static Result<HttpServer> bind(SocketAddr addr);

    [[nodiscard]] NET_EXPORT const TcpListener& listener() const
    {
        return m_inner;
    }

    NET_EXPORT void add_route(
        HttpMethod method, const std::string& path, const RouteHandler& handler)
    {
        m_routes[method][path] = handler;
    }

    // TODO: Add support for path parameters.

    [[nodiscard]] NET_EXPORT Result<void> run() const;

private:
    [[nodiscard]] Result<std::pair<HttpRequest, HttpConnection>> accept() const;

    [[nodiscard]] Result<void> handle_request(
        const net::HttpConnection& conn, const HttpRequest& req) const;

    explicit HttpServer(TcpListener inner)
        : m_inner { std::move(inner) }
    {
    }

    TcpListener m_inner;
    std::unordered_map<HttpMethod,
        std::unordered_map<std::string, RouteHandler>>
        m_routes;
    bool m_running { true };
};
} // namespace net
