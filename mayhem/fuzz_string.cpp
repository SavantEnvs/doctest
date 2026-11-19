// Fuzz doctest::String, the string type doctest uses for every test name, message and stringified
// value. Its small-buffer/heap representation is where upstream fixed a stack buffer overflow in the
// String(const char*, size) constructor (46f4c46f1a, issue #460).
//
// Input: byte 0 = length of the first string, then the string bytes, then the rest of the input is
// an op stream. Strings are copied into exact-size heap buffers WITHOUT a NUL terminator, which is
// what the String(const char*, size) contract allows, so ASan sees any over-read.
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_POSIX_SIGNALS
#include "doctest.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>

using doctest::String;
typedef String::size_type sz_t;
static const size_t kMaxLen = 1 << 16;

namespace {
struct Reader {
    const uint8_t *d;
    size_t n;
    size_t pos;
    bool more() const { return pos < n; }
    uint8_t byte() { return pos < n ? d[pos++] : 0; }
    // returns an exact-size, unterminated heap copy of up to `want` bytes
    std::unique_ptr<char[]> chunk(size_t want, size_t *got) {
        size_t len = want < n - pos ? want : n - pos;
        std::unique_ptr<char[]> buf(new char[len ? len : 1]);
        if (len)
            std::memcpy(buf.get(), d + pos, len);
        pos += len;
        *got = len;
        return buf;
    }
};

void check(const String &s) {
    // c_str() must always be NUL-terminated at size()
    if (s.c_str()[s.size()] != '\0')
        std::abort();
}

String make(Reader &r) {
    size_t want = r.byte();
    if (want >= 0xf0)
        want = (want - 0xf0) * 64 + 64; // larger heap-backed strings
    size_t got = 0;
    auto buf = r.chunk(want, &got);
    String s(buf.get(), static_cast<sz_t>(got));
    if (s.size() != got || std::memcmp(s.c_str(), buf.get(), got) != 0)
        std::abort();
    check(s);
    return s;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Reader r{data, size, 0};
    String a = make(r);
    String b;
    int steps = 0;
    while (r.more() && steps++ < 64) {
        uint8_t op = r.byte();
        switch (op % 14) {
        case 0: b = make(r); break;
        // concatenation is capped: swap + += grows the strings exponentially across 64 ops
        case 1: if (a.size() + b.size() < kMaxLen) a += b; break;
        case 2: if (a.size() + b.size() < kMaxLen) a = a + b; break;
        case 3: {
            sz_t pos = r.byte(), cnt = r.byte();
            if (pos <= a.size())
                b = a.substr(pos, cnt == 0xff ? String::npos : cnt);
            break;
        }
        case 4: {
            sz_t p = r.byte();
            if (p <= a.size())
                b = String(a).substr(p);
            break;
        }
        case 5: (void)a.find(static_cast<char>(r.byte()), r.byte()); break;
        case 6: (void)a.rfind(static_cast<char>(r.byte()), r.byte() == 0xff ? String::npos : r.byte()); break;
        case 7: (void)a.compare(b, (r.byte() & 1) != 0); break;
        case 8: (void)(a == b); (void)(a < b); (void)(a >= b); (void)(a != b); break;
        case 9: { String c(a); a = std::move(b); b = std::move(c); break; }
        case 10: { String c(std::move(a)); a = c; break; }
        case 11: {
            sz_t i = r.byte();
            if (i < a.size())
                a[i] = static_cast<char>(r.byte());
            break;
        }
        case 12: {
            size_t got = 0;
            auto buf = r.chunk(r.byte(), &got);
            std::istringstream in(std::string(buf.get(), got));
            b = String(in, static_cast<sz_t>(got));
            if (b.size() != got)
                std::abort();
            break;
        }
        case 13: {
            std::ostringstream os;
            os << a << doctest::toString(b);
            (void)a.compare(os.str().c_str(), true);
            break;
        }
        }
        check(a);
        check(b);
        (void)a.capacity();
    }
    return 0;
}
