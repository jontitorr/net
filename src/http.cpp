#include <algorithm>
#include <cassert>
#include <cstring>
#include <net/http.hpp>
#include <numeric>

#ifdef _WIN32
#define NOMINMAX
#include <WS2tcpip.h>
#include <WinSock2.h>
#else
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#endif

namespace {
using net::HttpHeaders;
using net::HttpMethod;
using net::HttpRequest;
using net::HttpResponse;
using net::HttpStatus;
using net::Ipv4Addr;
using net::Ipv6Addr;
using net::Result;
using net::SocketAddr;
using net::SocketAddrV4;
using net::SocketAddrV6;
using net::Uri;
using net::http::status_message;

void init()
{
    [[maybe_unused]] static const auto _ = [] {
#ifdef _WIN32
        WSADATA wsa_data {};
        [[maybe_unused]] const auto res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        assert(res == 0);
#endif
        return 0;
    }();
}

bool iequals(std::string_view a, std::string_view b)
{
    return std::equal(a.begin(), a.end(), b.begin(), b.end(),
        [](char l, char r) { return std::tolower(l) == std::tolower(r); });
}

Result<HttpMethod> http_method_from_str(std::string_view str)
{
    using enum HttpMethod;

    if (str == "GET") {
        return Get;
    }
    if (str == "POST") {
        return Post;
    }
    if (str == "PUT") {
        return Put;
    }
    if (str == "DELETE") {
        return Delete;
    }
    if (str == "HEAD") {
        return Head;
    }
    if (str == "OPTIONS") {
        return Options;
    }
    if (str == "PATCH") {
        return Patch;
    }

    return tl::make_unexpected(
        std::make_error_code(std::errc::invalid_argument));
}

Result<std::string> http_method_to_str(const HttpMethod method)
{
    switch (method) {
        using enum HttpMethod;
    case Get:
        return "GET";
    case Post:
        return "POST";
    case Put:
        return "PUT";
    case Delete:
        return "DELETE";
    case Head:
        return "HEAD";
    case Options:
        return "OPTIONS";
    case Patch:
        return "PATCH";
    default:
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }
}

std::vector<std::string> split(std::string_view s, std::string_view delimiter)
{
    std::vector<std::string> ret {};
    size_t pos {};
    size_t prev {};

    while ((pos = s.find(delimiter, prev)) != std::string::npos) {
        ret.emplace_back(s.substr(prev, pos - prev));
        prev = pos + delimiter.length();
    }

    ret.emplace_back(s.substr(prev));
    return ret;
}

bool is_number(std::string_view s)
{
    return std::all_of(
        s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); });
}

void parse_chunked(std::string& body)
{
    std::string new_body {};

    for (size_t i {}; i < body.length(); i += 2) {
        // If we have reached the end of the chunked body, we are done.
        if (body[i] == '0' && body[i + 1] == '\r' && body[i + 2] == '\n'
            && body[i + 3] == '\r' && body[i + 4] == '\n') {
            break;
        }

        auto chunk_size_start = i;

        // Skip until we are the end of the chunk size.
        while (body[i] != '\r' && body[i + 1] != '\n') {
            ++i;
        }

        const auto chunk_size_end = i;

        // Skip the CRLF.
        i += 2;

        const auto chunk_size_str
            = body.substr(chunk_size_start, chunk_size_end - chunk_size_start);
        // We now have the chunk size (which is always a hex number).
        const auto chunk_size = std::stoul(chunk_size_str, nullptr, 16);

        new_body.reserve(new_body.length() + chunk_size);
        new_body.append(body.substr(i, chunk_size));
        i += chunk_size;
    }

    body = std::move(new_body);
}

std::string ltrim(std::string_view s)
{
    const auto it = std::find_if_not(
        s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); });
    return { it, s.end() };
}

HttpHeaders parse_headers(std::string_view headers)
{
    HttpHeaders ret {};

    for (const auto& header : split(headers, "\r\n")) {
        const auto colon_pos = header.find(':');

        if (colon_pos == std::string::npos) {
            continue;
        }

        const auto key = header.substr(0, colon_pos);
        const auto value = ltrim(header.substr(colon_pos + 1));

        ret.emplace(key, value);
    }

    return ret;
}

Result<HttpResponse> receive_http_response(auto& stream)
{
    HttpResponse response {};
    std::string response_str(1024, '\0');
    size_t end_of_headers {};
    size_t response_len {};

    do {
        const auto old_length = response_len;

        // We can only write starting from the old length, because we
        // wouldn't want to overwrite the previous data.
        const auto res = stream.read(std::as_writable_bytes(
            std::span { response_str }.subspan(old_length)));

        if (!res) {
            return tl::make_unexpected(res.error());
        }

        if (response_len + *res >= response_str.length()) {
            response_str.resize((response_str.length() + *res) * 2);
        }

        response_len += *res;
        end_of_headers = response_str.find("\r\n\r\n");
    } while (end_of_headers == std::string::npos);

    response_str.resize(response_len);

    auto body = response_str.substr(end_of_headers + 4);

    response_str.resize(end_of_headers + 2);

    auto end_of_status = response_str.find("\r\n");

    if (end_of_status == std::string::npos) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    auto status_line = split(
        std::string_view { response_str }.substr(0, end_of_status), " ");

    if (status_line.size() < 3 || !is_number(status_line[1])) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    response.status_code = static_cast<HttpStatus>(std::stoi(status_line[1]));
    response.status_message
        = std::accumulate(status_line.begin() + 2, status_line.end(),
            status_line.front(), [](auto a, auto b) { return a + " " + b; });

    response.headers = parse_headers(
        std::string_view { response_str }.substr(end_of_status + 2));

    const size_t content_length = response.headers.contains("Content-Length")
        ? std::stoul(response.headers.at("Content-Length"))
        : 0;

    const auto encoded = response.headers.contains("Transfer-Encoding")
        && response.headers.at("Transfer-Encoding") == "chunked";

    auto bytes_received = body.length();
    body.resize(std::max(content_length, bytes_received));

    while (bytes_received < content_length) {
        const auto res = stream.read(
            std::as_writable_bytes(std::span { body }.subspan(bytes_received)));

        if (!res) {
            return tl::make_unexpected(res.error());
        }

        if (*res == 0) {
            return tl::make_unexpected(
                std::make_error_code(std::errc::connection_reset));
        }

        bytes_received += *res;
    }

    if (encoded) {
        body.resize(bytes_received + 1024);
        auto end_of_chunk = body.find("0\r\n\r\n");

        while (end_of_chunk == std::string::npos) {
            const auto res = stream.read(std::as_writable_bytes(
                std::span { body }.subspan(bytes_received)));

            if (!res) {
                return tl::make_unexpected(res.error());
            }

            if (*res == 0) {
                return tl::make_unexpected(
                    std::make_error_code(std::errc::connection_reset));
            }

            if (bytes_received + *res >= body.length()) {
                body.resize((body.length() + *res) * 2);
            }

            bytes_received += *res;
            end_of_chunk = body.find("0\r\n\r\n");
        }

        body.resize(bytes_received);
        parse_chunked(body);
    }

    response.body = std::move(body);
    return response;
}

Result<HttpRequest> receive_http_request(auto& stream)
{
    std::string request_str(1024, '\0');
    size_t end_of_headers {};
    size_t request_len {};

    do {
        const auto old_length = request_len;

        const auto res = stream.read(std::as_writable_bytes(
            std::span { request_str }.subspan(old_length)));

        if (!res) {
            return tl::make_unexpected(res.error());
        }

        if (*res == 0) {
            return tl::make_unexpected(
                std::make_error_code(std::errc::connection_reset));
        }

        if (request_len + *res >= request_str.length()) {
            request_str.resize((request_str.length() + *res) * 2);
        }

        request_len += *res;
        end_of_headers = request_str.find("\r\n\r\n");
    } while (end_of_headers == std::string::npos);

    request_str.resize(request_len);

    auto body = request_str.substr(end_of_headers + 4);

    request_str.resize(end_of_headers + 2);

    auto end_of_request_line = request_str.find("\r\n");

    if (end_of_request_line == std::string::npos) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    auto request_line = split(
        std::string_view { request_str }.substr(0, end_of_request_line), " ");

    if (request_line.size() != 3) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    // Method should be specified in all caps.
    if (!std::all_of(request_line.front().begin(), request_line.front().end(),
            [](char c) { return std::isupper(c); })) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    auto method = http_method_from_str(request_line.front());

    if (!method) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    auto& uri = request_line[1];

    // TODO: Check for valid version.
    // TODO: Since we are also only handling HTTP/1.1, we have to return some
    // invalid version error, which we should handle. auto http_version =
    // [&last_line = request_line.back()] {
    //     std::string_view ret { last_line };
    //     ret.remove_suffix(2);
    //     return ret;
    // }();

    const auto headers
        = parse_headers(request_str.substr(end_of_request_line + 2));

    const auto content_length = [&headers]() -> size_t {
        if (headers.contains("Content-Length")) {
            return static_cast<size_t>(
                std::stoull(headers.at("Content-Length")));
        }

        return 0;
    }();

    auto bytes_received = body.length();
    body.resize(std::max(content_length, bytes_received));

    while (bytes_received < content_length) {
        const auto res = stream.read(
            std::as_writable_bytes(std::span { body }.subspan(bytes_received)));

        if (!res) {
            return tl::make_unexpected(res.error());
        }

        if (*res == 0) {
            return tl::make_unexpected(
                std::make_error_code(std::errc::connection_reset));
        }

        bytes_received += *res;
    }

    return HttpRequest {
        .method = *method, .path = uri, .body = body, .headers = headers
    };
}

Result<void> send_http_response(const auto& stream, const HttpResponse& res)
{
    auto status_str = status_message(res.status_code);
    std::string response_str {};

    response_str.append("HTTP/1.1 ")
        .append(std::to_string(static_cast<int>(res.status_code)))
        .append(" ")
        .append(status_str)
        .append("\r\n");

    for (const auto& [key, value] : res.headers) {
        if (iequals(key, "Content-Length")) {
            continue;
        }

        response_str.append(key).append(": ").append(value).append("\r\n");
    }

    if (!res.body.empty()) {
        response_str.append("Content-Length: ")
            .append(std::to_string(res.body.length()))
            .append("\r\n");
    }

    response_str.append("\r\n").append(res.body);

    if (const auto r = stream.write(std::as_bytes(std::span { response_str }));
        !r) {
        return tl::make_unexpected(r.error());
    }

    return {};
}

Result<HttpResponse> send_http_request(
    const auto& stream, const Uri& uri, const HttpRequest& req, bool keep_alive)
{
    auto method_str = http_method_to_str(req.method);

    if (!method_str) {
        return tl::make_unexpected(method_str.error());
    }

    auto line = std::move(*method_str);

    line.append(" ").append(uri.path.empty() ? "/" : uri.path);

    if (!uri.query.empty()) {
        line.append("?").append(
            std::accumulate(std::next(uri.query.begin()), uri.query.end(),
                uri.query.begin()->first + '=' + uri.query.begin()->second,
                [](auto a, auto b) {
                    if (b.second.empty()) {
                        return a + '&' + b.first;
                    }

                    return a + '&' + b.first + '=' + b.second;
                }));
    }

    if (!uri.fragment.empty()) {
        line.append('#' + uri.fragment);
    }

    line.append(" HTTP/1.1\r\n")
        .append("Host: ")
        .append(uri.host)
        .append("\r\n");

    for (const auto& [key, value] : req.headers) {
        if (iequals(key, "Keep-Alive")) {
            continue;
        }

        line.append(key).append(": ").append(value).append("\r\n");
    }

    if (!keep_alive) {
        line.append("Connection: close\r\n");
    }

    if (!req.body.empty()) {
        line.append("Content-Length: ")
            .append(std::to_string(req.body.length()))
            .append("\r\n");
    }

    line.append("\r\n").append(req.body);

    if (const auto res = stream.write(std::as_bytes(std::span { line }));
        !res) {
        return tl::make_unexpected(res.error());
    }

    return receive_http_response(stream);
}

Result<SocketAddr> lookup_address(const std::string& host, int port)
{
    init();

    addrinfo hints {};
    hints.ai_family = host.find(':') == std::string::npos ? AF_INET : AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result {};

    if (const auto res = getaddrinfo(
            host.c_str(), std::to_string(port).c_str(), &hints, &result);
        res != 0) {
        return tl::make_unexpected(
            std::make_error_code(static_cast<std::errc>(res)));
    }

    switch (result->ai_family) {
    case AF_INET: {
        auto addr_in = *reinterpret_cast<sockaddr_in*>(result->ai_addr);

        std::array<std::byte, 4> octets {};

        std::memcpy(octets.data(), &addr_in.sin_addr, 4);
        freeaddrinfo(result);

        return SocketAddrV4::create(
            Ipv4Addr::create(octets), static_cast<uint16_t>(port));
    }
    case AF_INET6: {
        auto addr_in = *reinterpret_cast<sockaddr_in6*>(result->ai_addr);

        std::array<std::byte, 16> octets {};

        std::memcpy(octets.data(), &addr_in.sin6_addr, 16);
        freeaddrinfo(result);

        return SocketAddrV6::create(
            Ipv6Addr::create(octets), static_cast<uint16_t>(port));
    }
    default:
        freeaddrinfo(result);
        return tl::make_unexpected(
            std::make_error_code(std::errc::address_family_not_supported));
    }
}
} // namespace

namespace net {
constexpr std::string_view method_name(HttpMethod method)
{
    switch (method) {
        using enum net::HttpMethod;
    case Get:
        return "GET";
    case Post:
        return "POST";
    case Put:
        return "PUT";
    case Delete:
        return "DELETE";
    case Head:
        return "HEAD";
    case Options:
        return "OPTIONS";
    case Connect:
        return "CONNECT";
    case Trace:
        return "TRACE";
    case Patch:
        return "PATCH";
    default:
        return "UNKNOWN";
    }
}

Result<HttpConnection> HttpConnection::connect(std::string_view url)
{
    auto uri = Uri::parse(url);

    if (uri.scheme.empty()
        || (!iequals(uri.scheme, "http") && !iequals(uri.scheme, "https"))) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    if (!uri.port) {
        uri.port
            = iequals(uri.scheme, "http") ? uint16_t { 80 } : uint16_t { 443 };
    }

    // TODO: Make lookup_address the third method of parsing for SocketAddr.
    auto addr = lookup_address(uri.host, *uri.port);

    if (!addr) {
        return tl::make_unexpected(addr.error());
    }

    auto conn = TcpStream::connect(*addr);

    if (!conn) {
        return tl::make_unexpected(conn.error());
    }

    if (iequals(uri.scheme, "http")) {
        return HttpConnection { std::move(*conn),
            uri.scheme + "://" + uri.host };
    }

    auto ssl = SslProvider::create(SslMethod::TlsClient);

    if (!ssl) {
        return tl::make_unexpected(ssl.error());
    }

    auto ssl_stream = ssl->connect(uri.host, std::move(*conn));

    if (!ssl_stream) {
        return tl::make_unexpected(ssl_stream.error());
    }

    return HttpConnection { std::move(*ssl_stream),
        uri.scheme + "://" + uri.host };
}

Result<HttpResponse> HttpConnection::send_request(
    std::string_view url, const HttpRequest& req)
{
    using enum HttpMethod;

    if (req.method != Get && req.method != Post && req.method != Put
        && req.method != Delete && req.method != Head && req.method != Options
        && req.method != Connect && req.method != Trace
        && req.method != Patch) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    const auto conn = HttpConnection::connect(url);

    if (!conn) {
        return tl::make_unexpected(conn.error());
    }

    const auto uri = Uri::parse(std::string { url } + req.path);

    return std::visit(
        [&uri, &req](const auto& stream) {
            return send_http_request(stream, uri, req, true);
        },
        conn->m_inner);
}

Result<void> HttpConnection::respond(const HttpResponse& res) const
{
    return std::visit(
        [&res](const auto& stream) { return send_http_response(stream, res); },
        m_inner);
}

Result<HttpResponse> HttpConnection::request(const HttpRequest& req) const
{
    using enum HttpMethod;

    if ((req.method != Get && req.method != Post && req.method != Put
            && req.method != Delete && req.method != Head
            && req.method != Options && req.method != Connect
            && req.method != Trace && req.method != Patch)
        || req.path.empty() || req.path.front() != '/') {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    auto uri = Uri::parse(m_base_url + req.path);

    return std::visit(
        [&req, &uri](const auto& stream) {
            return send_http_request(stream, uri, req, true);
        },
        m_inner);
}

namespace http {
Result<HttpResponse> get(std::string_view url)
{
    return HttpConnection::send_request(url,
        { .method = HttpMethod::Get, .path = {}, .body = {}, .headers = {} });
}

Result<HttpResponse> get(std::string_view url, const HttpHeaders& headers)
{
    return HttpConnection::send_request(url,
        { .method = HttpMethod::Get,
            .path = {},
            .body = {},
            .headers = headers });
}

Result<HttpResponse> post(std::string_view url, const std::string& body)
{
    return HttpConnection::send_request(url,
        { .method = HttpMethod::Post,
            .path = {},
            .body = body,
            .headers = {} });
}

Result<HttpResponse> put(std::string_view url, const std::string& body)
{
    return HttpConnection::send_request(url,
        { .method = HttpMethod::Put, .path = {}, .body = body, .headers = {} });
}

constexpr std::string_view status_message(HttpStatus status)
{
#define STATUS_CODE_CASE(code, msg)                                            \
    case code:                                                                 \
        return msg;

    switch (status) {
        using enum HttpStatus;

        STATUS_CODE_CASE(Continue, "Continue");
        STATUS_CODE_CASE(SwitchingProtocols, "Switching Protocols");
        STATUS_CODE_CASE(Processing, "Processing");
        STATUS_CODE_CASE(EarlyHints, "Early Hints");
        STATUS_CODE_CASE(Ok, "OK");
        STATUS_CODE_CASE(Created, "Created");
        STATUS_CODE_CASE(Accepted, "Accepted");
        STATUS_CODE_CASE(
            NonAuthoritativeInformation, "Non-Authoritative Information");
        STATUS_CODE_CASE(NoContent, "No Content");
        STATUS_CODE_CASE(ResetContent, "Reset Content");
        STATUS_CODE_CASE(PartialContent, "Partial Content");
        STATUS_CODE_CASE(MultiStatus, "Multi-Status");
        STATUS_CODE_CASE(AlreadyReported, "Already Reported");
        STATUS_CODE_CASE(IMUsed, "IM Used");
        STATUS_CODE_CASE(MultipleChoices, "Multiple Choices");
        STATUS_CODE_CASE(MovedPermanently, "Moved Permanently");
        STATUS_CODE_CASE(Found, "Found");
        STATUS_CODE_CASE(SeeOther, "See Other");
        STATUS_CODE_CASE(NotModified, "Not Modified");
        STATUS_CODE_CASE(UseProxy, "Use Proxy");
        STATUS_CODE_CASE(TemporaryRedirect, "Temporary Redirect");
        STATUS_CODE_CASE(PermanentRedirect, "Permanent Redirect");
        STATUS_CODE_CASE(BadRequest, "Bad Request");
        STATUS_CODE_CASE(Unauthorized, "Unauthorized");
        STATUS_CODE_CASE(PaymentRequired, "Payment Required");
        STATUS_CODE_CASE(Forbidden, "Forbidden");
        STATUS_CODE_CASE(NotFound, "Not Found");
        STATUS_CODE_CASE(MethodNotAllowed, "Method Not Allowed");
        STATUS_CODE_CASE(NotAcceptable, "Not Acceptable");
        STATUS_CODE_CASE(
            ProxyAuthenticationRequired, "Proxy Authentication Required");
        STATUS_CODE_CASE(RequestTimeout, "Request Timeout");
        STATUS_CODE_CASE(Conflict, "Conflict");
        STATUS_CODE_CASE(Gone, "Gone");
        STATUS_CODE_CASE(LengthRequired, "Length Required");
        STATUS_CODE_CASE(PreconditionFailed, "Precondition Failed");
        STATUS_CODE_CASE(PayloadTooLarge, "Payload Too Large");
        STATUS_CODE_CASE(URITooLong, "URI Too Long");
        STATUS_CODE_CASE(UnsupportedMediaType, "Unsupported Media Type");
        STATUS_CODE_CASE(RangeNotSatisfiable, "Range Not Satisfiable");
        STATUS_CODE_CASE(ExpectationFailed, "Expectation Failed");
        STATUS_CODE_CASE(ImATeapot, "I'm a teapot");
        STATUS_CODE_CASE(MisdirectedRequest, "Misdirected Request");
        STATUS_CODE_CASE(UnprocessableEntity, "Unprocessable Entity");
        STATUS_CODE_CASE(Locked, "Locked");
        STATUS_CODE_CASE(FailedDependency, "Failed Dependency");
        STATUS_CODE_CASE(TooEarly, "Too Early");
        STATUS_CODE_CASE(UpgradeRequired, "Upgrade Required");
        STATUS_CODE_CASE(PreconditionRequired, "Precondition Required");
        STATUS_CODE_CASE(TooManyRequests, "Too Many Requests");
        STATUS_CODE_CASE(
            RequestHeaderFieldsTooLarge, "Request Header Fields Too Large");
        STATUS_CODE_CASE(
            UnavailableForLegalReasons, "Unavailable For Legal Reasons");
        STATUS_CODE_CASE(InternalServerError, "Internal Server Error");
        STATUS_CODE_CASE(NotImplemented, "Not Implemented");
        STATUS_CODE_CASE(BadGateway, "Bad Gateway");
        STATUS_CODE_CASE(ServiceUnavailable, "Service Unavailable");
        STATUS_CODE_CASE(GatewayTimeout, "Gateway Timeout");
        STATUS_CODE_CASE(HTTPVersionNotSupported, "HTTP Version Not Supported");
        STATUS_CODE_CASE(VariantAlsoNegotiates, "Variant Also Negotiates");
        STATUS_CODE_CASE(InsufficientStorage, "Insufficient Storage");
        STATUS_CODE_CASE(LoopDetected, "Loop Detected");
        STATUS_CODE_CASE(NotExtended, "Not Extended");
        STATUS_CODE_CASE(
            NetworkAuthenticationRequired, "Network Authentication Required");

    default:
        return "Unknown";
    }

#undef STATUS_CODE_CASE
}
} // namespace http

Result<HttpServer> HttpServer::bind(SocketAddr addr)
{
    auto listener = TcpListener::bind(addr);

    if (!listener) {
        return tl::make_unexpected(listener.error());
    }

    return HttpServer { std::move(*listener) };
}

Result<void> HttpServer::run() const
{
    std::unordered_map<RawSocket, HttpConnection> connections;
    // TODO: Maybe abstract the pollfd stuff into a class?
    std::vector<pollfd> events { pollfd {
        m_inner.as_raw_socket(), POLLIN, 0 } };
    auto num_events = events.size();

    const auto add_connection
        = [&connections, &events, &num_events](HttpConnection&& conn) {
              const auto fd = conn.as_raw_socket();
              connections.emplace(fd, std::move(conn));
              events.emplace_back(pollfd { fd, POLLIN, 0 });
              ++num_events;
          };

    const auto remove_connection = [&connections, &events, &num_events](
                                       RawSocket fd) {
        connections.erase(fd);
        events.erase(std::remove_if(events.begin(), events.end(),
                         [fd](const auto& event) { return event.fd == fd; }),
            events.end());
        --num_events;
    };

    const auto accept_new_connection
        = [this, &add_connection]() -> Result<void> {
        auto client = accept();

        if (!client) {
            return tl::make_unexpected(client.error());
        }

        auto [req, conn] = std::move(*client);

        if (const auto res = handle_request(conn, req); !res) {
            if (res.error() != std::errc::connection_reset) {
                return tl::make_unexpected(res.error());
            }

            return {};
        }

        add_connection(std::move(conn));
        return {};
    };

    const auto handle_connection = [this, &connections, &remove_connection](
                                       RawSocket fd) -> Result<void> {
        auto& conn = connections.at(fd);

        auto req = std::visit(
            [](const auto& stream) { return receive_http_request(stream); },
            conn.m_inner);

        if (!req) {
            if (req.error() != std::errc::connection_reset) {
                return tl::make_unexpected(req.error());
            }

            remove_connection(fd);
            return {};
        }

        if (const auto res = handle_request(conn, *req); !res) {
            if (res.error() != std::errc::connection_reset) {
                return tl::make_unexpected(res.error());
            }

            remove_connection(fd);
            return {};
        }

        return {};
    };

    while (m_running) {
#ifdef _WIN32
        if (::WSAPoll(events.data(), static_cast<ULONG>(num_events), -1) < 0) {
            return tl::make_unexpected(
                std::error_code(WSAGetLastError(), std::system_category()));
        }
#else
        if (::poll(events.data(), num_events, -1) < 0) {
            return tl::make_unexpected(
                std::error_code(errno, std::system_category()));
        }
#endif
        for (size_t i {}; i < num_events; ++i) {
            const auto& event = events.at(i);

            if ((event.revents & POLLIN) == 0) {
                continue;
            }

            if (event.fd == m_inner.as_raw_socket()) {
                if (const auto res = accept_new_connection(); !res) {
                    if (res.error() != std::errc::connection_reset) {
                        return tl::make_unexpected(res.error());
                    }
                }
            } else {
                if (const auto res = handle_connection(event.fd); !res) {
                    if (res.error() != std::errc::connection_reset) {
                        return tl::make_unexpected(res.error());
                    }
                }
            }
        }
    }

    return {};
}

Result<std::pair<HttpRequest, HttpConnection>> HttpServer::accept() const
{
    auto stream = m_inner.accept();

    if (!stream) {
        return tl::make_unexpected(stream.error());
    }

    // We can only accept the client once they send a proper Http Request.
    auto req = receive_http_request(stream->first);

    if (!req) {
        return tl::make_unexpected(req.error());
    }

    return std::make_pair(
        std::move(*req), HttpConnection { std::move(stream->first), "" });
}

Result<void> HttpServer::handle_request(
    const net::HttpConnection& conn, const HttpRequest& req) const
{
    const auto path = Uri::parse(req.path).path;

    if (!m_routes.contains(req.method)
        || !m_routes.at(req.method).contains(path)) {
        if (const auto res = conn.respond({ .status_code = HttpStatus::NotFound,
                .status_message = {},
                .body = {},
                .headers = { { "Connection", "close" } } });
            !res) {
            return tl::make_unexpected(res.error());
        };

        return tl::make_unexpected(
            std::make_error_code(std::errc::connection_reset));
    }

    const auto response = m_routes.at(req.method).at(path)(req);

    if (const auto res = conn.respond(response); !res) {
        return tl::make_unexpected(res.error());
    }

    if (response.headers.contains("Connection")
        && response.headers.at("Connection") == "close") {
        return tl::make_unexpected(
            std::make_error_code(std::errc::connection_reset));
    }

    return {};
}
} // namespace net
