#include <iostream>
#include <net/ws.hpp>
#include <random>
#include <thread>

using net::WebSocketClientBuilder;
using net::WebSocketMessage;

int main()
{
    auto client = WebSocketClientBuilder()
                      .with_on_message([](const WebSocketMessage& msg) {
                          const auto data = std::string_view {
                              reinterpret_cast<const char*>(msg.payload.data()),
                              msg.payload.size()
                          };

                          std::cout << "(CLIENT) Received message: " << data
                                    << '\n';
                      })
                      .with_url("ws://localhost:8080")
                      .build();

    if (!client) {
        std::cout << "WebsocketClient Build Error: " << client.error().message()
                  << '\n';
        return 1;
    }

    static std::array<char, 63> alphanum { "0123456789"
                                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                           "abcdefghijklmnopqrstuvwxyz" };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, alphanum.size() - 1);

    std::thread send_thread([&client, &dis, &gen] {
        std::this_thread::sleep_for(std::chrono::seconds { 5 });

        for (size_t i {}; i < 100'000; ++i) {
            std::string message(1024 * 1024, '\0');

            std::generate_n(message.begin(), message.size(),
                [&] { return alphanum.at(dis(gen)); });

            const auto result = client->send(message);

            if (!result) {
                std::cout << "Websocket Client Send Error: "
                          << result.error().message() << '\n';
                return;
            }
        }
    });

    client->run();
    send_thread.join();
}
