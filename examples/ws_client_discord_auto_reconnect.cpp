#include <iostream>
#include <net/ws.hpp>
#include <thread>

int main()
{
    std::atomic_bool connected {};
    std::atomic_bool running { true };

    auto client
        = net::WebSocketClientBuilder {}
              .with_auto_reconnect(true)
              .with_on_close([&connected](net::WebSocketCloseCode code,
                                 std::string_view reason) {
                  std::cout << "Connection closed | code="
                            << static_cast<uint16_t>(code)
                            << " | reason=" << reason << '\n';
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

    std::thread t([&client, &connected, &running] {
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds { 5 });

            if (!connected) {
                continue;
            }

            if (client->close(static_cast<net::WebSocketCloseCode>(4000))) {
                std::cout << "Sending close code 4000\n";
            }
        }
    });

    if (const auto res = client->run(); !res) {
        std::cout << "Error running client: " << res.error().message() << '\n';
        running = false;
    }

    t.join();
}
