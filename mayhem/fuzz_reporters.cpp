// Fuzz doctest's reporters and stringification: the XML (XmlEncode/XmlWriter), JUnit and console
// reporters encode test names, subcase names, INFO/CAPTURE context, assertion messages, expression
// text and exception messages that come from the code under test — this target makes all of those
// attacker-controlled.
//
// Input: byte 0 picks the reporter and flags (success/duration/no-path/minimal/...), the rest is split
// on NUL into strings the TEST_CASEs below use as subcase names, messages, thrown exception text and
// numbers for Approx. Per-input state: a fresh Context per input writing to an in-memory sink; the
// string list is reset before every run.
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_POSIX_SIGNALS // keep ASan/libFuzzer in charge of fatal signals
#include "doctest.h"

#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::vector<std::string> g_str;
std::string at(size_t i) { return g_str.empty() ? std::string() : g_str[i % g_str.size()]; }
doctest::String ds(const std::string &s) {
    return doctest::String(s.data(), static_cast<doctest::String::size_type>(s.size()));
}
double num(size_t i) { return std::strtod(at(i).c_str(), nullptr); }

struct CustomError {
    std::string msg;
};
} // namespace

REGISTER_EXCEPTION_TRANSLATOR(const CustomError &e) { return ds(e.msg); }

TEST_CASE("messages and context") {
    std::string a = at(0), b = at(1);
    INFO("first: ", ds(a));
    CAPTURE(b);
    CHECK_MESSAGE(a == b, ds(at(2)));
    CHECK(ds(a) == ds(b));
    CHECK(ds(a).compare(ds(b), true) == 0);
    MESSAGE(ds(at(3)));
    FAIL_CHECK(ds(at(4)));
    WARN_EQ(a.size(), b.size());
}

TEST_CASE("dynamic subcases") {
    for (size_t i = 0; i < g_str.size() && i < 8; ++i) {
        SUBCASE(at(i).c_str()) {
            INFO(ds(at(i + 1)));
            CHECK_EQ(ds(at(i)), ds(at(i + 2)));
        }
    }
}

TEST_CASE("exceptions") {
    CHECK_THROWS_WITH(throw std::runtime_error(at(5)), ds(at(6)).c_str());
    CHECK_THROWS_AS(throw CustomError{at(7)}, std::runtime_error);
    CHECK_NOTHROW(throw std::logic_error(at(8)));
}

TEST_CASE("throws out of the test case") {
    if (!at(9).empty() && (at(9)[0] & 1))
        throw CustomError{at(9)};
    if (!at(9).empty())
        throw std::runtime_error(at(9));
}

TEST_CASE("approx and numbers") {
    double x = num(10), y = num(11);
    CHECK(x == doctest::Approx(y).epsilon(num(12)));
    CHECK_LT(x, y);
    CHECK(doctest::toString(x) == ds(at(13)));
    CHECK(doctest::toString(static_cast<float>(y)) == doctest::toString(at(13).c_str()));
}

TEST_CASE("contains matcher") {
    CHECK_THROWS_WITH(throw std::runtime_error(at(14)), doctest::Contains(at(15).c_str()));
    CHECK(ds(at(14)) == doctest::Contains(at(15).c_str()));
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t flags = size ? data[0] : 0;
    g_str.clear();
    std::string cur;
    for (size_t i = 1; i < size; ++i) {
        if (data[i] == 0) {
            g_str.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(static_cast<char>(data[i]));
        }
    }
    g_str.push_back(cur);

    static const char *const reporters[] = {"console", "xml", "junit", "console,xml"};
    std::ostringstream sink;
    doctest::Context ctx;
    ctx.setOption("reporters", reporters[flags & 3]);
    ctx.setOption("success", (flags & 4) != 0);
    ctx.setOption("duration", (flags & 8) != 0);
    ctx.setOption("no-path-filenames", (flags & 16) != 0);
    ctx.setOption("minimal", (flags & 32) != 0);
    ctx.setOption("no-skipped-summary", (flags & 64) != 0);
    ctx.setOption("no-colors", (flags & 128) == 0);
    ctx.setOption("no-breaks", true);
    ctx.setCout(&sink);
    ctx.run();
    return 0;
}
