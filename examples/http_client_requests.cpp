#include <iostream>
#include <net/http.hpp>

int main()
{
    const std::array<net::HttpMethod, 5> methods {
        net::HttpMethod::Get,
        net::HttpMethod::Post,
        net::HttpMethod::Put,
        net::HttpMethod::Delete,
        net::HttpMethod::Patch,
    };

    const auto* url = "http://httpbin.org/";

    for (const auto& method : methods) {
        const auto res = net::http::request(url, {
            .method = method,
            .path = "/anything",
            .body = "Hello, world!",
            .headers = {
                { "Content-Type", "text/plain" },
            },
        });

        if (!res) {
            std::cout << "Error: " << res.error().message() << '\n';
            return 1;
        }

        std::cout << "Status code: " << static_cast<uint8_t>(res->status_code)
                  << '\n';
        std::cout << "Status message: " << res->status_message << '\n';
        std::cout << "Body: " << res->body << '\n';
    }
}
