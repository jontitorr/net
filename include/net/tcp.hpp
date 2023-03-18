#pragma once
#include <net/socket.hpp>
#include <optional>

namespace net {
struct NET_EXPORT TcpStream {
    static Result<TcpStream> connect(SocketAddr addr);

    bool operator==(const TcpStream& other) const
    {
        return as_raw_socket() == other.as_raw_socket();
    }

    [[nodiscard]] const Socket& socket() const { return m_inner; }

    [[nodiscard]] RawSocket as_raw_socket() const
    {
        return m_inner.as_raw_socket();
    }

    [[nodiscard]] Result<size_t> peek(tcb::span<std::byte> buf) const
    {
        return m_inner.peek(buf);
    }

    [[nodiscard]] Result<size_t> read(tcb::span<std::byte> buf) const
    {
        return m_inner.read(buf);
    }

    [[nodiscard]] Result<size_t> write(tcb::span<const std::byte> data) const
    {
        return m_inner.write(data);
    }

    [[nodiscard]] Result<void> flush() const { return {}; }

    [[nodiscard]] Result<void> shutdown(Socket::Shutdown how) const
    {
        return m_inner.shutdown(how);
    }

    [[nodiscard]] Result<void> set_nonblocking(bool nonblocking) const
    {
        return m_inner.set_nonblocking(nonblocking);
    }

private:
    friend struct TcpListener;

    explicit TcpStream(Socket inner)
        : m_inner { std::move(inner) }
    {
    }

    Socket m_inner;
};

struct NET_EXPORT TcpListener {
    static Result<TcpListener> bind(SocketAddr addr);

    [[nodiscard]] const Socket& socket() const { return m_inner; }

    [[nodiscard]] RawSocket as_raw_socket() const
    {
        return m_inner.as_raw_socket();
    }

    [[nodiscard]] Result<std::pair<TcpStream, SocketAddr>> accept() const;

    struct Incoming {
        explicit Incoming(const TcpListener& listener)
            : m_listener { listener }
        {
        }

        Incoming(const Incoming&) = delete;
        Incoming& operator=(const Incoming&) = delete;
        Incoming(Incoming&&) = delete;
        Incoming& operator=(Incoming&&) = delete;
        ~Incoming() = default;

        struct Iterator {
            explicit Iterator(const TcpListener& listener,
                std::optional<TcpStream> current = std::nullopt)
                : m_listener { listener }
                , m_current { std::move(current) }
            {
            }

            Iterator(const Iterator&) = delete;
            Iterator& operator=(const Iterator&) = delete;
            Iterator(Iterator&&) = delete;
            Iterator& operator=(Iterator&&) = delete;
            ~Iterator() = default;

            TcpStream operator*() { return std::move(*m_current); }

            Iterator& operator++()
            {
                if (auto accept_res = m_listener.accept(); accept_res) {
                    auto& [stream, _] = *accept_res;
                    m_current = std::move(stream);
                } else {
                    m_current = std::nullopt;
                }

                return *this;
            }

            bool operator==(const Iterator& other) const
            {
                return m_current == other.m_current;
            }

            bool operator!=(const Iterator& other) const
            {
                return !(*this == other);
            }

        private:
            const TcpListener& m_listener;
            std::optional<TcpStream> m_current;
        };

        [[nodiscard]] Iterator begin() const
        {
            if (auto accept_res = m_listener.accept(); accept_res) {
                auto& [stream, _] = *accept_res;
                return Iterator { m_listener, std::move(stream) };
            }

            return Iterator { m_listener };
        }

        [[nodiscard]] Iterator end() const { return Iterator { m_listener }; }

    private:
        const TcpListener& m_listener;
    };

    /**
     * @brief Returns an iterator over the connections being received on this
     * listener. Iterating over it is equivalent to calling TcpListener::accept
     * in a loop.
     *
     * @return Incoming An iterator over the connections being received on this
     * listener.
     */
    [[nodiscard]] Incoming incoming() const { return Incoming { *this }; }

private:
    explicit TcpListener(Socket inner)
        : m_inner { std::move(inner) }
    {
    }

    Socket m_inner;
};
} // namespace net
