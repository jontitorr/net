#include <iostream>
#include <net/ssl.hpp>

using net::SocketAddr;
using net::SslMethod;
using net::SslProvider;
using net::TcpStream;

int print_error_code(const std::error_code& ec)
{
    std::cout << "Category: " << ec.category().name() << '\n'
              << "Value:    " << ec.value() << '\n'
              << "Message:  " << ec.message() << "\n\n";

    return 1;
}

int main()
{
    auto client = TcpStream::connect(
        *SocketAddr::parse("142.250.191.206:443")); // google.com

    if (!client) {
        return print_error_code(client.error());
    }

    auto ssl_stream
        = SslProvider::create(SslMethod::Tls)->connect(std::move(*client));

    if (!ssl_stream) {
        return print_error_code(ssl_stream.error());
    }

    const auto sent = ssl_stream->write(std::as_bytes(
        std::span { "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n" }));

    if (!sent) {
        std::cout << "(Client) Failed to write to server.\n";
        return 1;
    }

    std::cout << "(Client) Sent " << *sent << " bytes.\n";

    std::array<std::byte, 1024> buf {};

    const auto read
        = ssl_stream->read(std::as_writable_bytes(std::span { buf }));

    if (!read) {
        std::cout << "(Client) Failed to read from server.\n";
        return 1;
    }

    std::cout << "(Client) Read " << *read << " bytes.\n";

    std::cout << "(Client) Received: "
              << std::string_view { reinterpret_cast<char*>(buf.data()), *read }
              << '\n';
}
