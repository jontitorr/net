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

        std::printf("Status code: %hu\n", res->status_code);
        std::printf("Status message: %s\n", res->status_message.c_str());
        std::printf("Body: %s\n", res->body.c_str());
    };

    do_request(
        { .method = HttpMethod::Get, .path = "/", .body = {}, .headers = {} });
    do_request({ .method = HttpMethod::Get,
        .path = "/search",
        .body = {},
        .headers = {} });
}
