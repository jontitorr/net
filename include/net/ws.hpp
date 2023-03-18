#pragma once
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <net/http.hpp>
#include <queue>
#include <utility>

namespace net {
enum class WebSocketOpcode : uint8_t {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
};

enum class WebSocketError : uint8_t {
    None,
    InvalidOpcode,
    InvalidPayloadLength,
    InvalidMaskingKey,
};

enum class WebSocketCloseCode : uint16_t {
    Normal = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    NoStatus = 1005,
    Abnormal = 1006,
    InvalidPayload = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MissingExtension = 1010,
    InternalError = 1011,
    ServiceRestart = 1012,
    TryAgainLater = 1013,
    BadGateway = 1014,
    TlsHandshake = 1015,
};

struct WebSocketCloseFrame {
    WebSocketCloseCode code;
    std::string reason;
};

struct WebSocketMessage {
    bool is_text;
    std::vector<std::byte> payload;
};

struct WebSocketClient {
    NET_EXPORT WebSocketClient& set_auto_reconnect(bool reconnect)
    {
        m_state->auto_reconnect.store(reconnect);
        return *this;
    }

    NET_EXPORT Result<void> send(std::string_view message);
    NET_EXPORT Result<void> close(
        WebSocketCloseCode code = WebSocketCloseCode::Normal,
        std::string_view reason = "");
    NET_EXPORT Result<void> run();

private:
    friend struct WebSocketClientBuilder;

    WebSocketClient(Uri uri, const std::function<void()>& on_close,
        const std::function<void()>& on_connect,
        const std::function<void(WebSocketMessage)>& on_message,
        bool auto_reconnect)
        : m_uri { std::move(uri) }
        , m_on_close { on_close }
        , m_on_connect { on_connect }
        , m_on_message { on_message }
    {
        m_state->auto_reconnect.store(auto_reconnect);
    }

    [[nodiscard]] Result<void> connect();
    void disconnect();
    void heartbeat_loop();
    void read_loop();
    void poll();
    void process_data(std::vector<std::byte>& data);

    struct RawMessage {
        WebSocketOpcode opcode;
        std::vector<std::byte> payload;
    };

    Result<void> send_raw(const RawMessage& message);

    std::optional<HttpConnection> m_http_connection;
    Uri m_uri;
    std::function<void()> m_on_close;
    std::function<void()> m_on_connect;
    std::function<void(WebSocketMessage)> m_on_message;
    std::vector<std::byte> m_read_buffer;
    std::queue<RawMessage> m_write_queue;
    std::optional<std::byte> m_leftover_byte;
    std::optional<WebSocketOpcode> m_leftover_opcode;

    /// Flags for indicating which side has sent over the CLOSE frame.
    struct CloseFlags {
        uint8_t client : 1;
        uint8_t server : 1;
    };

    CloseFlags m_close_flags { 0, 0 };

    enum class ConnectionState : uint8_t {
        Connecting,
        Connected,
        Disconnecting,
        Disconnected,
    };

    struct State {
        std::atomic<ConnectionState> connection_state {
            ConnectionState::Disconnected
        };

        struct Flag {
            void clear()
            {
                std::unique_lock lock { m_mtx };
                m_value = false;
            }

            void set()
            {
                std::unique_lock lock { m_mtx };
                m_value = true;
                m_cv.notify_all();
            }

            void wait(bool old)
            {
                std::unique_lock lock { m_mtx };
                m_cv.wait(lock, [this, old] { return m_value != old; });
            }

            void notify_one() { m_cv.notify_one(); }

        private:
            bool m_value {};
            std::condition_variable m_cv;
            std::mutex m_mtx;
        };

        std::atomic_bool missed_heartbeat;
        Flag activity_flag;
        Flag heartbeat_flag;
        Flag read_flag;
        mutable std::mutex heartbeat_mtx;
        mutable std::mutex mtx;
        std::condition_variable cv;
        std::atomic_bool auto_reconnect;
    };

    std::unique_ptr<State> m_state { std::make_unique<State>() };
};

struct WebSocketClientBuilder {
    NET_EXPORT WebSocketClientBuilder() = default;
    WebSocketClientBuilder(const WebSocketClientBuilder&) = delete;
    WebSocketClientBuilder& operator=(const WebSocketClientBuilder&) = delete;
    WebSocketClientBuilder(WebSocketClientBuilder&&) = delete;
    WebSocketClientBuilder& operator=(WebSocketClientBuilder&&) = delete;
    NET_EXPORT ~WebSocketClientBuilder() = default;

    NET_EXPORT WebSocketClientBuilder& with_url(std::string_view url)
    {
        m_url = url;
        return *this;
    }

    NET_EXPORT WebSocketClientBuilder& with_auto_reconnect(bool auto_reconnect)
    {
        m_auto_reconnect = auto_reconnect;
        return *this;
    }

    NET_EXPORT WebSocketClientBuilder& with_on_close(
        const std::function<void()>& on_close)
    {
        m_on_close = on_close;
        return *this;
    }

    NET_EXPORT WebSocketClientBuilder& with_on_connect(
        const std::function<void()>& on_connect)
    {
        m_on_connect = on_connect;
        return *this;
    }

    NET_EXPORT WebSocketClientBuilder& with_on_message(
        const std::function<void(WebSocketMessage)>& on_message)
    {
        m_on_message = on_message;
        return *this;
    }

    [[nodiscard]] NET_EXPORT Result<WebSocketClient> build() const;

private:
    std::string m_url;
    bool m_auto_reconnect {};
    std::function<void()> m_on_close;
    std::function<void()> m_on_connect;
    std::function<void(WebSocketMessage)> m_on_message;
};

// TODO: WebSocketServer
} // namespace net
