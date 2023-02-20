#include <iostream>
#include <net/ws.hpp>
#include <thread>

int main()
{
    std::atomic_bool connected {};

    auto client
        = net::WebSocketClientBuilder {}
              .with_auto_reconnect(true)
              .with_on_close([&connected] {
                  std::cout << "Connection closed\n";
                  connected = false;
              })
              .with_on_connect([&connected] {
                  std::cout << "Connected\n";
                  connected = true;
              })
              .with_on_message([](net::WebSocketMessage msg) {
                  std::cout << "Received message: "
                            << std::string_view { reinterpret_cast<const char*>(
                                                      msg.payload.data()),
                                   msg.payload.size() }
                            << '\n';
              })
              .with_url("wss://gateway.discord.gg/?v=10&encoding=json")
              .build();

    std::jthread t([&client, &connected] {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(5));

            if (!connected) {
                continue;
            }

            std::cout << "Sending close code 4000\n";
            client->close(static_cast<net::WebSocketCloseCode>(4000));
        }
    });

    client->run();
}
