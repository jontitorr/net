#include <net/uri.hpp>
#include <net/ws.hpp>
#include <thread>

#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-value"
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wuseless-cast"
#endif
#endif
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif

namespace {
std::string compute_ws_accept(std::string_view key)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Don't use newlines

    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    EVP_DigestUpdate(ctx, key.data(), key.size());
    EVP_DigestUpdate(ctx, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);

    std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
    unsigned int hash_len;

    EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(ctx);

    BIO_write(bio, hash.data(), static_cast<int>(hash_len));
#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-value"
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wuseless-cast"
#endif
#endif
    BIO_flush(bio);

    char* base64;
    const auto base64_len = static_cast<size_t>(BIO_get_mem_data(bio, &base64));

    std::string result(base64, base64_len);

    BIO_free_all(bio);

    return result;
}

constexpr size_t MASKING_KEY_SIZE { 4 };

std::array<std::byte, MASKING_KEY_SIZE> generate_masking_key()
{
    std::array<std::byte, MASKING_KEY_SIZE> key;
    RAND_bytes(reinterpret_cast<unsigned char*>(key.data()),
        static_cast<int>(key.size()));
    return key;
}

std::string generate_ws_key()
{
    std::vector<unsigned char> buffer(16);
    RAND_bytes(buffer.data(), static_cast<int>(buffer.size()));

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Don't use newlines

    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer.data(), static_cast<int>(buffer.size()));
#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
    BIO_flush(bio);

    char* base64;
    const auto base64_len = BIO_get_mem_data(bio, &base64);
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif

    return std::string(base64, static_cast<size_t>(base64_len));
}

bool iequals(std::string_view a, std::string_view b)
{
    return a.length() == b.length()
        && std::equal(a.begin(), a.end(), b.begin(),
            [](char l, char r) { return std::tolower(l) == std::tolower(r); });
}

std::string get_path_query_fragment(const net::Uri& uri)
{
    std::string ret;

    ret += uri.path.empty() ? "/" : uri.path;

    if (!uri.query.empty()) {
        ret += '?';

        for (const auto& [key, value] : uri.query) {
            ret += key;

            if (!value.empty()) {
                ret += '=';
                ret += value;
            }

            ret += '&';
        }

        ret.pop_back();
    }

    if (!uri.fragment.empty()) {
        ret += '#';
        ret += uri.fragment;
    }

    return ret;
}

inline net::Result<void> http_set_nonblocking(
    const net::HttpConnection& conn, bool nonblocking)
{
    return std::visit(
        [nonblocking](const auto& stream) {
            return stream.socket().set_nonblocking(nonblocking);
        },
        conn.stream());
}

inline net::Result<void> http_poll_socket(const net::HttpConnection& http_conn,
    int timeout_ms, net::Socket::PollEvent want)
{
    return std::visit(
        [timeout_ms, want](const auto& stream) {
            return stream.socket().poll(timeout_ms, want);
        },
        http_conn.stream());
}

template<typename Stream, typename Container>
net::Result<void> read_until_size_is(
    const Stream& stream, Container& container, size_t target_size)
{
    if (container.size() < target_size) {
        auto needed = target_size - container.size();
        container.resize(container.size() + needed);

        do {
            const auto res = stream.read(
                std::as_writable_bytes(std::span { container }.subspan(
                    container.size() - needed, needed)));

            if (!res) {
                return tl::make_unexpected(res.error());
            }

            if (*res == 0) {
                return tl::make_unexpected(
                    std::make_error_code(std::errc::connection_reset));
            }

            needed -= *res;
        } while (needed > 0);
    }

    return {};
}

constexpr std::array<std::byte, 3> HEARTBEAT_MESSAGE
    = { std::byte { 0x9 }, std::byte { 0x0 }, std::byte { 0x0 } };
} // namespace

namespace net {
Result<void> WebSocketClient::send(std::string_view message)
{
    const auto message_span = std::as_bytes(std::span(message));
    return send_raw({ .opcode = WebSocketOpcode::Text,
        .payload = std::vector(message_span.begin(), message_span.end()) });
}

Result<void> WebSocketClient::close(
    WebSocketCloseCode code, std::string_view reason)
{
    if (const auto state = m_state->state.load();
        state == WebSocketState::Closing || state == WebSocketState::Closed) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::not_connected));
    }

    m_state->state.store(WebSocketState::Closing);

    const auto reason_span = std::as_bytes(std::span(reason));

    std::vector<std::byte> payload;
    payload.reserve(2 + reason.size());
    payload.push_back(static_cast<std::byte>(static_cast<uint16_t>(code) >> 8));
    payload.push_back(static_cast<std::byte>(static_cast<uint16_t>(code)));
    payload.insert(payload.end(), reason_span.begin(), reason_span.end());

    return send_raw(
        { .opcode = WebSocketOpcode::Close, .payload = std::move(payload) });
}

Result<void> WebSocketClient::run()
{
    do {
        if (auto connect_res = connect(); !connect_res) {
            return tl::make_unexpected(connect_res.error());
        }

        {
            std::scoped_lock lk { m_state->mtx };

            if (m_on_connect) {
                m_on_connect();
            }
        }

        std::jthread heartbeat_thread { &WebSocketClient::heartbeat_loop,
            this };
        std::jthread read_thread { &WebSocketClient::read_loop, this };

        while (m_state->state.load() != WebSocketState::Closed) {
            m_state->activity_flag.wait(false);
            poll();
        }
    } while (m_state->auto_reconnect.load());

    return {};
}

Result<void> WebSocketClient::connect() const
{
    if (const auto state = m_state->state.load();
        state == WebSocketState::Connecting || state == WebSocketState::Open) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::already_connected));
    }

    const auto key = generate_ws_key();
    const HttpHeaders headers { { "Connection", "Upgrade" },
        { "Upgrade", "websocket" }, { "Sec-WebSocket-Version", "13" },
        { "Sec-WebSocket-Key", key } };

    http_set_nonblocking(m_http_connection, false);

    const auto res = m_http_connection.request({ .method = HttpMethod::Get,
        .path = m_path,
        .body = {},
        .headers = headers });

    http_set_nonblocking(m_http_connection, true);

    if (!res) {
        return tl::make_unexpected(res.error());
    }

    if (res->status_code != HttpStatus::SwitchingProtocols) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::connection_refused));
    }

    if (!res->headers.contains("Upgrade")
        || !iequals(res->headers.at("Upgrade"), "websocket")) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::connection_refused));
    }

    if (!res->headers.contains("Connection")
        || !iequals(res->headers.at("Connection"), "upgrade")) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::connection_refused));
    }

    if (!res->headers.contains("Sec-WebSocket-Accept")
        || res->headers.at("Sec-WebSocket-Accept") != compute_ws_accept(key)) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::connection_refused));
    }

    m_state->state.store(WebSocketState::Open);

    return {};
}

void WebSocketClient::disconnect()
{
    if (const auto state = m_state->state.load();
        state != WebSocketState::Open && state != WebSocketState::Closing) {
        return;
    }

    m_state->state.store(WebSocketState::Closed);
    m_http_connection.disconnect();

    {
        std::scoped_lock lk { m_state->mtx };

        if (m_on_close) {
            m_on_close();
        }

        m_close_flags = {};
        m_read_buffer.clear();
        m_write_queue = {};
    }

    m_state->activity_flag.test_and_set();
    m_state->activity_flag.notify_one();
    m_state->cv.notify_one();
    m_state->heartbeat_flag.clear();
    m_state->heartbeat_flag.notify_one();
    m_state->read_flag.clear();
    m_state->read_flag.notify_one();
}

void WebSocketClient::heartbeat_loop()
{
    while (m_state->state.load() == WebSocketState::Open
        && send_raw({ .opcode = WebSocketOpcode::Ping,
            .payload = std::vector<std::byte>(
                HEARTBEAT_MESSAGE.begin(), HEARTBEAT_MESSAGE.end()) })) {
        m_state->missed_heartbeats.fetch_add(1);
        m_state->heartbeat_flag.test_and_set();
        m_state->heartbeat_flag.wait(true);

        if (m_state->state.load() != WebSocketState::Open) {
            break;
        }

        {
            static constexpr std::chrono::seconds heartbeat_interval { 30 };

            std::unique_lock lk { m_state->heartbeat_mtx };
            m_state->cv.wait_for(lk, heartbeat_interval, [this] {
                return m_state->state.load() != WebSocketState::Open;
            });
        }

        if (m_state->missed_heartbeats.load() >= 3) {
            return disconnect();
        }
    }
}

void WebSocketClient::read_loop()
{
    while ((m_state->state.load() != WebSocketState::Closed
               && http_poll_socket(m_http_connection,
                   Socket::PollTimeout::Infinite, Socket::PollEvent::Read))
        || m_state->state.load() == WebSocketState::Closing) {
        // We found data to be read.
        m_state->read_flag.test_and_set();
        // Notify the main thread that we have work to do.
        m_state->activity_flag.test_and_set();
        m_state->activity_flag.notify_one();
        // Wait for the main thread to finish processing the data.
        m_state->read_flag.wait(true);
    }
}

void WebSocketClient::poll()
{
    if (m_state->state.load() == WebSocketState::Closed) {
        return;
    }

    std::vector<std::byte> buf(1024);

    auto res = std::visit(
        [&buf](const auto& stream) {
            return stream.read(std::as_writable_bytes(std::span { buf }));
        },
        m_http_connection.stream());

    if (!res && res.error() != std::errc::resource_unavailable_try_again) {
        return disconnect();
    }

    if (res) {
        if (*res == 0) {
            return disconnect();
        }

        buf.resize(*res);
        process_data(buf);
    }

    {
        std::unique_lock lk { m_state->mtx };

        if (m_close_flags.client && m_close_flags.server) {
            lk.unlock();
            return disconnect();
        }
    }

    {
        std::scoped_lock lk { m_state->mtx };

        while (!m_write_queue.empty()) {
            const auto frame = std::move(m_write_queue.front());

            m_write_queue.pop();

            res = std::visit(
                [&payload = frame.payload](const auto& stream) {
                    return stream.write(std::as_bytes(std::span { payload }));
                },
                m_http_connection.stream());

            if (!res) {
                return disconnect();
            }

            // If that message was a close frame, empty the rest of the write
            // buffer.
            if (frame.opcode == WebSocketOpcode::Close) {
                m_close_flags.client = 1;
                m_write_queue = {};
            } else if (frame.opcode == WebSocketOpcode::Ping) {
                m_state->heartbeat_flag.clear();
                m_state->heartbeat_flag.notify_one();
            }
        }
    }

    m_state->activity_flag.clear();
    m_state->activity_flag.notify_one();
    m_state->read_flag.clear();
    m_state->read_flag.notify_one();
}

void WebSocketClient::process_data(std::vector<std::byte>& data)
{
    // Used for laying out our WebSocket frames for ease of use.
    struct WebSocketFrame {
        WebSocketOpcode opcode;
        bool fin;
        bool mask;
        uint64_t payload_length;
        std::array<std::byte, MASKING_KEY_SIZE> masking_key;
        std::vector<std::byte> payload;
    };

    // Our data must be at least 2 bytes long to be a valid WebSocket frame.
    while (!data.empty() && data.size() >= 2) {
        // Because of the edge case of the first frame being so big it takes
        // most of
        // the buffer, having an incomplete (less than 2 bytes) frame remaining,
        // we have to check if there's a leftover byte.
        if (m_leftover_byte) {
            data.insert(data.begin(), *m_leftover_byte);
            m_leftover_byte = std::nullopt;
        }

        // Processing our WebSocket Frames.
        WebSocketFrame frame { .opcode = static_cast<WebSocketOpcode>(
                                   (data[0] & std::byte { 0b00001111 })),
            .fin = static_cast<bool>((data[0] & std::byte { 0b10000000 }) >> 7),
            .mask
            = static_cast<bool>((data[1] & std::byte { 0b10000000 }) >> 7),
            .payload_length
            = static_cast<uint64_t>(data[1] & std::byte { 0b01111111 }),
            .masking_key {},
            .payload {} };

        const auto payload_start = [&frame] {
            uint8_t ret { 2 };

            if (frame.payload_length == 126) {
                ret += 2;
            } else if (frame.payload_length == 127) {
                ret += 8;
            }

            if (frame.mask) {
                ret += MASKING_KEY_SIZE;
            }

            return ret;
        }();

        // If for some reason we do not have the complete header for the frame,
        // we must fetch it.
        if (const auto res = std::visit(
                [&data, payload_start](const auto& stream) {
                    return read_until_size_is(stream, data, payload_start);
                },
                m_http_connection.stream());
            !res) {
            return disconnect();
        }

        if (frame.payload_length == 126) {
            frame.payload_length = uint64_t { static_cast<uint8_t>(data[2]) }
                    << 8
                | uint64_t { static_cast<uint8_t>(data[3]) };
        } else if (frame.payload_length == 127) {
            frame.payload_length = uint64_t { static_cast<uint8_t>(data[2]) }
                    << 56
                | uint64_t { static_cast<uint8_t>(data[3]) } << 48
                | uint64_t { static_cast<uint8_t>(data[4]) } << 40
                | uint64_t { static_cast<uint8_t>(data[5]) } << 32
                | uint64_t { static_cast<uint8_t>(data[6]) } << 24
                | uint64_t { static_cast<uint8_t>(data[7]) } << 16
                | uint64_t { static_cast<uint8_t>(data[8]) } << 8
                | uint64_t { static_cast<uint8_t>(data[9]) };
        }

        if (frame.mask) {
            std::copy(data.begin() + payload_start - MASKING_KEY_SIZE,
                data.begin() + payload_start, frame.masking_key.begin());
        }

        // If we don't have the complete payload, we must fetch it.
        if (const auto res = std::visit(
                [&data, payload_length = frame.payload_length, payload_start](
                    const auto& stream) {
                    return read_until_size_is(
                        stream, data, payload_start + payload_length);
                },
                m_http_connection.stream());
            !res) {
            return disconnect();
        }

        frame.payload = std::vector(data.begin() + payload_start,
            data.begin() + payload_start
                + static_cast<ptrdiff_t>(frame.payload_length));

        if (frame.mask) {
            std::transform(frame.payload.begin(), frame.payload.end(),
                frame.payload.begin(),
                [&masking_key = frame.masking_key, i = size_t {}](
                    const auto& byte) mutable {
                    return byte ^ masking_key.at(i++ % MASKING_KEY_SIZE);
                });
        }

        switch (frame.opcode) {
        case WebSocketOpcode::Continuation:
        case WebSocketOpcode::Text:
        case WebSocketOpcode::Binary: {
            std::unique_lock lk { m_state->mtx };

            if (!m_leftover_opcode) {
                m_leftover_opcode = frame.opcode;
            }

            m_read_buffer.insert(m_read_buffer.end(), frame.payload.begin(),
                frame.payload.end());

            if (frame.fin) {
                WebSocketMessage message {
                    .is_text = *m_leftover_opcode == WebSocketOpcode::Text,
                    .payload = std::move(m_read_buffer),
                };

                m_read_buffer.clear();
                m_leftover_opcode.reset();

                lk.unlock();

                if (m_on_message) {
                    m_on_message(std::move(message));
                }
            }

            break;
        }
        case WebSocketOpcode::Close: {
            m_close_flags.server = 1;
            close();
            break;
        }
        case WebSocketOpcode::Ping: {
            send_raw({ WebSocketOpcode::Pong, std::move(frame.payload) });
            break;
        }
        case WebSocketOpcode::Pong: {
            if (std::equal(frame.payload.begin(), frame.payload.end(),
                    HEARTBEAT_MESSAGE.begin())) {
                m_state->missed_heartbeats.store(0);
            }
            break;
        }
        default: {
            return disconnect();
        }
        }

        const auto processed_bytes
            = static_cast<ptrdiff_t>(payload_start + frame.payload_length);

        data.erase(data.begin(), data.begin() + processed_bytes);

        if (data.size() == 1) {
            m_leftover_byte = data.front();
            data.clear();
        }
    }
}

Result<void> WebSocketClient::send_raw(const RawMessage& message)
{
    if (const auto state = m_state->state.load();
        state != WebSocketState::Open && state != WebSocketState::Closing) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::not_connected));
    }

    const auto masking_key = generate_masking_key();
    const auto payload_size = message.payload.size();

    std::vector<std::byte> frame;
    frame.reserve(2 + masking_key.size() + payload_size);

    // FIN bit, opcode
    frame.push_back(
        static_cast<std::byte>(message.opcode) | std::byte { 0b10000000 });

    // Mask bit, payload length
    if (payload_size < 126) {
        frame.push_back(
            static_cast<std::byte>(payload_size) | std::byte { 0b10000000 });
    } else if (payload_size < 65536) {
        frame.push_back(std::byte { 126 } | std::byte { 0b10000000 });
        frame.push_back(static_cast<std::byte>(payload_size >> 8));
        frame.push_back(static_cast<std::byte>(payload_size));
    } else {
        frame.push_back(std::byte { 127 } | std::byte { 0b10000000 });
        frame.push_back(static_cast<std::byte>((payload_size >> 56) & 0xFF));
        frame.push_back(static_cast<std::byte>((payload_size >> 48) & 0xFF));
        frame.push_back(static_cast<std::byte>((payload_size >> 40) & 0xFF));
        frame.push_back(static_cast<std::byte>((payload_size >> 32) & 0xFF));
        frame.push_back(static_cast<std::byte>((payload_size >> 24) & 0xFF));
        frame.push_back(static_cast<std::byte>((payload_size >> 16) & 0xFF));
        frame.push_back(static_cast<std::byte>((payload_size >> 8) & 0xFF));
        frame.push_back(static_cast<std::byte>(payload_size & 0xFF));
    }

    // Masking key
    frame.insert(frame.end(), masking_key.begin(), masking_key.end());

    // Payload
    std::transform(message.payload.begin(), message.payload.end(),
        std::back_inserter(frame),
        [&masking_key, i = size_t {}](auto byte) mutable {
            return byte ^ masking_key.at(i++ % MASKING_KEY_SIZE);
        });

    {
        std::scoped_lock lk { m_state->mtx };
        m_write_queue.emplace(RawMessage {
            .opcode = message.opcode, .payload = std::move(frame) });
    }

    m_state->activity_flag.test_and_set();
    m_state->activity_flag.notify_one();

    return {};
}

Result<WebSocketClient> WebSocketClientBuilder::build() const
{
    if (m_url.empty()) {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    auto uri = Uri::parse(m_url);

    if (uri.scheme != "ws" && uri.scheme != "wss") {
        return tl::make_unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }

    uri.scheme = uri.scheme == "ws" ? "http" : "https";

    auto http_client = HttpConnection::connect(uri.to_string());

    if (!http_client) {
        return tl::make_unexpected(http_client.error());
    }

    return WebSocketClient { std::move(*http_client),
        get_path_query_fragment(uri), m_on_close, m_on_connect, m_on_message,
        m_auto_reconnect };
}
} // namespace net
