#include <iostream>
#include <net/ssl.hpp>
#include <thread>

using net::SocketAddr;
using net::SslMethod;
using net::SslProvider;
using net::UdpSocket;

int print_error_code(const std::error_code& ec)
{
    std::cout << "Category: " << ec.category().name() << '\n'
              << "Value:    " << ec.value() << '\n'
              << "Message:  " << ec.message() << "\n\n";

    return 1;
}

int main()
{
    auto listener = UdpSocket::bind(*SocketAddr::parse("0.0.0.0:3030"));

    if (!listener) {
        return print_error_code(listener.error());
    }

    auto server_acceptor = *SslProvider::create(SslMethod::DtlsServer);

    const std::jthread client_thread { [] {
        auto client_connector = *SslProvider::create(SslMethod::DtlsClient);
        auto client = UdpSocket::bind(*SocketAddr::parse("0.0.0.0:0"));

        if (!client) {
            return print_error_code(client.error());
        }

        const auto connected
            = client->connect(*SocketAddr::parse("127.0.0.1:3030"));

        if (!connected) {
            std::cout << "(Client) Failed to RAW connect to server.\n";
            return print_error_code(connected.error());
        }

        std::cout << "(Client) RAW Connected to server.\n";

        auto ssl_stream
            = client_connector.connect("YOUR_HOST", std::move(*client));

        if (!ssl_stream) {
            std::cout << "(Client) Failed to SSL connect to server.\n";
            return 1;
        }

        std::cout << "(Client) SSL Connected to server.\n";

        const auto sent
            = ssl_stream->write(std::as_bytes(std::span { "Hello World!" }));

        std::cout << "(Client) Sent " << *sent << " bytes.\n";

        std::array<std::byte, 1024> buf {};

        const auto read
            = ssl_stream->read(std::as_writable_bytes(std::span { buf }));

        if (!read) {
            std::cout << "(Client) Failed to read from server.\n";
            return 1;
        }

        std::cout << "(Client) Read " << *read << " bytes.\n";
        std::cout << "(Client) Data: "
                  << std::string_view { reinterpret_cast<char*>(buf.data()),
                         *read }
                  << '\n';

        return 0;
    } };

    auto ssl_stream = server_acceptor.accept(std::move(*listener));

    if (!ssl_stream) {
        std::cout << "(Server) Failed to accept client: " << ssl_stream.error()
                  << '\n';
        return 1;
    }

    std::array<std::byte, 1024> buf {};

    const auto read
        = ssl_stream->read(std::as_writable_bytes(std::span { buf }));

    std::cout << "(Server) Read " << *read << " bytes.\n";

    const auto sent
        = ssl_stream->write(std::as_bytes(std::span { "Hello World!" }));

    std::cout << "(Server) Sent " << *sent << " bytes.\n";
}
