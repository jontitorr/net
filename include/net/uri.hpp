#pragma once
#include <map>
#include <net/export.h>
#include <optional>
#include <string>

namespace net {
struct CaseInsensitiveComp {
    bool operator()(std::string_view lkey, std::string_view rkey) const
    {
        return std::lexicographical_compare(lkey.begin(), lkey.end(),
            rkey.begin(), rkey.end(),
            [](const unsigned char& l, const unsigned char& r) {
                return std::tolower(l) < std::tolower(r);
            });
    }
};

using CaseInsensitiveMap
    = std::map<std::string, std::string, CaseInsensitiveComp>;
/**
 * @brief Represents a Uniform Resource Identifier commonly used in all HTTP(S)
 * requests.
 */
struct Uri {
    using QueryParams = CaseInsensitiveMap;

    /**
     * @brief Returns a URI object parsed from the given string.
     *
     * @param uri The string to parse.
     * @return Result<Uri> The parsed URI object.
     */
    [[nodiscard]] NET_EXPORT static Uri parse(std::string_view uri);
    [[nodiscard]] NET_EXPORT std::string to_string() const;

    std::string scheme {};
    std::string username {};
    std::string password {};
    std::string host {};
    std::optional<uint16_t> port {};
    std::string path {};
    QueryParams query {};
    std::string fragment {};

private:
    Uri() = default;
};
} // namespace net
