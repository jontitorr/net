#include <filesystem>
#include <fstream>
#include <net/http.hpp>

using net::HttpMethod;
using net::HttpResponse;
using net::HttpServer;
using net::HttpStatus;
using net::ServerHttpRequest;
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

    server->add_route(HttpMethod::Get, "/", [](const ServerHttpRequest& req) {
        const auto connection = req.headers.contains("Connection")
            ? req.headers.at("Connection")
            : "close";

        return HttpResponse {
            .status_code = HttpStatus::Ok,
            .status_message = "OK",
            .body = "<!DOCTYPE html><html><head><title>Hello, world!</title></head><body><h1>Hello, world!</h1></body></html>",
            .headers = {
                { "Content-Type", "text/html" },
                {"Connection", connection},
            },
        };
    });

    server->add_route(
        HttpMethod::Get, "/hello", [](const ServerHttpRequest& req) {
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

    server->add_route(HttpMethod::Get, "/hello/{waifu_name}",
        [](const ServerHttpRequest& req) {
            HttpResponse res;
            res.headers = {
                { "Content-Type", "text/plain" },
            };

            const auto& waifu_name = req.params.at("waifu_name");
            const auto waifu_res
                = net::http::get("https://api.jikan.moe/v4/anime?sfw&q="
                    + Uri::url_encode(waifu_name));

            if (!waifu_res) {
                res.status_code = HttpStatus::InternalServerError;
                res.status_message = "Internal Server Error";
                res.body = "Failed to fetch waifu";
                return res;
            }

            const auto& data = waifu_res->body;

            res.status_code = HttpStatus::Ok;
            res.status_message = "OK";
            res.body = data;
            return res;
        });

    server->add_route(
        HttpMethod::Post, "/hello", [](const ServerHttpRequest& req) {
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
