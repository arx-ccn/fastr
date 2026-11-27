#include "simdjson.h"

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace {
using namespace std::string_view_literals;
using simdjson::ondemand::object;

struct Span {
    const char *data;
    std::ptrdiff_t size;
};

enum class Field_Kind : std::uint8_t {
    end,
    ids,
    authors,
    kinds,
    since,
    until,
    limit,
    tag
};

template <typename T> struct Slice {
    const T *data;
    std::ptrdiff_t size;
};

union Value {
    Span text;
    std::int64_t number;
};

struct Field {
    std::int64_t number;
    std::ptrdiff_t start, count;
    Field_Kind kind;
    std::uint8_t tag;
};

struct Subscription {
    Span sid, hex;
    Slice<Field> fields;
    Slice<Value> values;
    std::ptrdiff_t filters;
};

// Bound the scratch retained by a connection thread after a large request.
constexpr std::size_t max_input = 16 * 1024;
struct Scratch {
    simdjson::ondemand::parser parser{max_input};
    std::vector<char> input;
    std::vector<Field> fields;
    std::vector<Value> values;
};

Span span(std::string_view s) {
    return {s.data(), static_cast<std::ptrdiff_t>(s.size())};
}

template <typename T> Slice<T> slice(const std::vector<T> &v) {
    return {v.data(), static_cast<std::ptrdiff_t>(v.size())};
}

bool read_filter(Scratch &s, object obj, std::ptrdiff_t max_values) {
    std::bitset<128 + 8> seen;
    for (auto field : obj) {
        std::string_view key = field.unescaped_key();
        Field f{};
        if (key == "ids"sv) {
            f.kind = Field_Kind::ids;
        } else if (key == "authors"sv) {
            f.kind = Field_Kind::authors;
        } else if (key == "kinds"sv) {
            f.kind = Field_Kind::kinds;
        } else if (key == "since"sv) {
            f.kind = Field_Kind::since;
        } else if (key == "until"sv) {
            f.kind = Field_Kind::until;
        } else if (key == "limit"sv) {
            f.kind = Field_Kind::limit;
        } else if (key.size() == 2 && key[0] == '#' &&
                   static_cast<unsigned char>(key[1]) < 128) {
            f.kind = Field_Kind::tag;
            f.tag = static_cast<unsigned char>(key[1]);
        } else {
            return false;
        }
        const auto index = static_cast<unsigned>(f.kind) + f.tag;
        if (seen[index]) {
            return false;
        }
        seen[index] = true;

        if (f.kind == Field_Kind::since || f.kind == Field_Kind::until ||
            f.kind == Field_Kind::limit) {
            f.number = field.value().get_int64();
            if (f.kind == Field_Kind::limit && f.number < 0) {
                return false;
            }
        } else {
            if (max_values < 0) {
                return false;
            }
            f.start = static_cast<std::ptrdiff_t>(s.values.size());
            for (auto value : field.value().get_array()) {
                if (f.count == max_values) {
                    return false;
                }
                if (f.kind == Field_Kind::kinds) {
                    std::int64_t kind = value.get_int64();
                    if (kind < 0 || kind > UINT16_MAX) {
                        return false;
                    }
                    s.values.push_back(Value{.number = kind});
                } else {
                    s.values.push_back(Value{.text = span(value.get_string())});
                }
                ++f.count;
            }
        }
        s.fields.push_back(f);
    }
    s.fields.push_back(Field{.kind = Field_Kind::end});
    return true;
}
} // namespace

// The views expire at the next call on this thread. Odin owns the final fields.
extern "C" int fastr_read_subscription(const char *raw, std::size_t size,
                                       std::ptrdiff_t max_values,
                                       Subscription *out) noexcept {
    if (size > max_input) {
        return 0;
    }
    static thread_local Scratch s;
    s.fields.clear();
    s.values.clear();
    try {
        const auto needed = size + simdjson::SIMDJSON_PADDING;
        if (s.input.size() < needed) {
            s.input.resize(needed);
        }
        std::memcpy(s.input.data(), raw, size);
        simdjson::ondemand::document doc =
            s.parser.iterate(s.input.data(), size, s.input.size());
        simdjson::ondemand::array root = doc.get_array();
        std::string_view verb;
        std::ptrdiff_t filters = 0;
        int i = 0;
        for (auto child : root) {
            if (i == 0) {
                verb = child.get_string();
            } else if (i == 1) {
                out->sid = span(child.get_string());
            } else if (verb == "REQ"sv || verb == "COUNT"sv ||
                       (verb == "NEG-OPEN"sv && i == 2)) {
                if (!read_filter(s, child.get_object(), max_values)) {
                    return 0;
                }
                ++filters;
            } else if ((verb == "NEG-MSG"sv && i == 2) ||
                       (verb == "NEG-OPEN"sv && i == 3)) {
                out->hex = span(child.get_string());
            } else {
                return 0;
            }
            ++i;
        }
        if (!doc.at_end() || i < 2 ||
            ((verb == "REQ"sv || verb == "COUNT"sv) && filters == 0) ||
            (verb == "NEG-OPEN"sv && i != 4) ||
            (verb == "NEG-MSG"sv && i != 3)) {
            return 0;
        }
        out->fields = slice(s.fields);
        out->values = slice(s.values);
        out->filters = filters;
        return 1;
    } catch (const simdjson::simdjson_error &) {
        return 0;
    } catch (const std::bad_alloc &) {
        return 0;
    }
}
