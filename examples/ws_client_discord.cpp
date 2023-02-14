#include <iostream>
#include <net/ws.hpp>

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
                      .with_on_close(
                          [] { std::cout << "(CLIENT) Connection closed\n"; })
                      .with_url("wss://gateway.discord.gg/?v=10&encoding=json")
                      .build();

    if (!client) {
        std::cout << "WebsocketClient Build Error: " << client.error().message()
                  << '\n';
        return 1;
    }

    if (const auto res = client->run(); !res) {
        std::cout << "WebsocketClient Run Error: " << res.error().message()
                  << '\n';
        return 1;
    }
}
