#include <iostream>
#include <net/http.hpp>

using net::HttpConnection;
using net::HttpMethod;
using net::HttpRequest;

int main()
{
    auto client = HttpConnection::connect("https://www.google.com/");

    if (!client) {
        std::printf("Error: %s\n", client.error().message().c_str());
        return 1;
    }

    const auto do_request = [&client](const HttpRequest& req) {
        auto res = client->request(req);

        if (!res) {
            std::printf("Error: %s\n", res.error().message().c_str());
            return;
        }

        std::cout << "Status code: " << static_cast<uint8_t>(res->status_code)
                  << '\n';
        std::cout << "Status message: " << res->status_message << '\n';
        std::cout << "Body: " << res->body << '\n';
    };

    do_request({ HttpMethod::Get, "/", {}, {} });
    do_request({ HttpMethod::Get, "/search", {}, {} });
}
