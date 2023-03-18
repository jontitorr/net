#include <iostream>
#include <net/ssl.hpp>
#include <thread>

using net::SocketAddr;
using net::SslFileType;
using net::SslMethod;
using net::SslProvider;
using net::TcpListener;
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
    // Creating a Tls Tcp Listener.
    auto listener = TcpListener::bind(*SocketAddr::parse("0.0.0.0:3030"));

    if (!listener) {
        return print_error_code(listener.error());
    }

    // Creating a Tls Acceptor.
    auto server_acceptor = *SslProvider::create(SslMethod::Tls);

    if (const auto res = server_acceptor.set_private_key_file(
            "server-private-key.pem", SslFileType::Pem);
        !res) {
        std::cout << "Failed to set private key file: " << res.error().message()
                  << '\n';
        return 1;
    }

    if (const auto res = server_acceptor.set_certificate_file(
            "server-certificate.pem", SslFileType::Pem);
        !res) {
        std::cout << "Failed to set certificate file: " << res.error().message()
                  << '\n';
        return 1;
    }

    std::thread client_thread { [] {
        auto client_acceptor = *SslProvider::create(SslMethod::Tls);
        auto client = TcpStream::connect(*SocketAddr::parse("127.0.0.1:3030"));

        if (!client) {
            return print_error_code(client.error());
        }

        auto ssl_stream
            = client_acceptor.connect("YOUR_HOST", std::move(*client));

        if (!ssl_stream) {
            return 1;
        }

        const auto sent
            = ssl_stream->write(tcb::as_bytes(tcb::span { "Hello World!" }));

        std::cout << "(Client) Sent " << *sent << " bytes.\n";

        std::array<std::byte, 1024> buf {};

        const auto read
            = ssl_stream->read(tcb::as_writable_bytes(tcb::span { buf }));

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

    // Tcp Loop.
    for (auto stream : listener->incoming()) {
        auto ssl_stream = server_acceptor.accept(std::move(stream));

        if (!ssl_stream) {
            std::cout << "Failed to accept SSL stream: "
                      << ssl_stream.error().message() << '\n';
                      client_thread.join();
            return 1;
        }

        std::array<std::byte, 1024> buf {};

        const auto read
            = ssl_stream->read(tcb::as_writable_bytes(tcb::span { buf }));

        std::cout << "(Server) Read " << *read << " bytes.\n";

        const auto sent
            = ssl_stream->write(tcb::as_bytes(tcb::span { "Hello World!" }));

        std::cout << "(Server) Sent " << *sent << " bytes.\n";
    }

    client_thread.join();
}
