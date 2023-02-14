#include <filesystem>
#include <fstream>
#include <net/http.hpp>

using net::HttpMethod;
using net::HttpRequest;
using net::HttpResponse;
using net::HttpServer;
using net::HttpStatus;
using net::SocketAddr;
using net::Uri;

std::string open_file(std::string_view path)
{
    namespace fs = std::filesystem;

    const fs::path file_path { path };

    if (!fs::exists(file_path)) {
        return "";
    }

    const std::ifstream file { file_path };
    std::stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}

int main()
{
    auto server = HttpServer::bind(*SocketAddr::parse("127.0.0.1:3000"));

    if (!server) {
        std::printf("Error: %s\n", server.error().message().c_str());
        return 1;
    }

    server->add_route(HttpMethod::Get, "/",
        [body = open_file("index.html")](const HttpRequest& req) {
            const auto connection = req.headers.contains("Connection")
                ? req.headers.at("Connection")
                : "close";

            return HttpResponse {
            .status_code = HttpStatus::Ok,
            .status_message = "OK",
            .body = body,
            .headers = {
                { "Content-Type", "text/html" },
                {"Connection", connection},
            },
        };
        });

    server->add_route(HttpMethod::Get, "/hello", [](const HttpRequest& req) {
        HttpResponse res;
        res.headers = {
            { "Content-Type", "text/plain" },
        };

        const auto query = Uri::parse(req.path).query;

        if (!query.contains("name")) {
            res.status_code = HttpStatus::BadRequest;
            res.status_message = "Bad Request";
            res.body = "Missing 'name' query parameter";
            return res;
        }

        const auto name = query.at("name");

        res.status_code = HttpStatus::Ok;
        res.status_message = "OK";
        res.body = "Hello, " + name + "!";
        return res;
    });

    server->add_route(HttpMethod::Post, "/hello", [](const HttpRequest& req) {
        return HttpResponse {
            .status_code = HttpStatus::Ok,
            .status_message = "OK",
            .body = "Hello, " + req.body + "!",
            .headers = {
                { "Content-Type", "text/plain" },
            },
        };
    });

    (void)server->run();
}
