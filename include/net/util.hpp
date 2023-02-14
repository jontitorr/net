#pragma once
#include <system_error>
#include <tl/expected.hpp>

namespace net {
template<typename T, typename E = std::error_code> using Result
    = tl::expected<T, E>;
} // namespace net
