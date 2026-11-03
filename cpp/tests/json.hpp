// A small JSON reader for the tests only (it allocates; the library does not).
// Integers only, which is all the fixture holds.

#ifndef LXPT_TEST_JSON_HPP
#define LXPT_TEST_JSON_HPP

#include <cstdint>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace json {

struct Value {
  enum Kind { Null, Bool, Int, Str, Arr, Obj } kind = Null;
  bool b = false;
  int64_t i = 0;
  std::string s;
  std::vector<Value> a;
  std::map<std::string, Value> o;

  const Value& operator[](const std::string& k) const {
    auto it = o.find(k);
    if (kind != Obj || it == o.end()) throw std::runtime_error("missing key " + k);
    return it->second;
  }
  const Value& operator[](size_t n) const { return a.at(n); }
  bool has(const std::string& k) const { return kind == Obj && o.count(k) != 0; }
  size_t size() const { return kind == Arr ? a.size() : o.size(); }
};

class Parser {
 public:
  explicit Parser(const std::string& t) : t_(t) {}
  Value parse() {
    Value v = value();
    ws();
    if (p_ != t_.size()) throw std::runtime_error("trailing JSON");
    return v;
  }

 private:
  const std::string& t_;
  size_t p_ = 0;
  void ws() {
    while (p_ < t_.size() && (t_[p_] == ' ' || t_[p_] == '\n' || t_[p_] == '\r' || t_[p_] == '\t')) p_++;
  }
  char peek() {
    ws();
    if (p_ >= t_.size()) throw std::runtime_error("JSON ends early");
    return t_[p_];
  }
  void expect(char c) {
    if (peek() != c) throw std::runtime_error(std::string("expected ") + c);
    p_++;
  }
  std::string str() {
    expect('"');
    std::string out;
    while (p_ < t_.size() && t_[p_] != '"') {
      if (t_[p_] == '\\') {
        p_++;
        const char c = t_[p_++];
        if (c == 'n') out += '\n';
        else if (c == 't') out += '\t';
        else if (c == 'u') {
          const long cp = std::strtol(t_.substr(p_, 4).c_str(), nullptr, 16);
          p_ += 4;
          if (cp < 0x80) out += char(cp);
          else throw std::runtime_error("non-ASCII \\u escape");
        } else out += c;
      } else {
        out += t_[p_++];
      }
    }
    expect('"');
    return out;
  }
  Value value() {
    Value v;
    const char c = peek();
    if (c == '{') {
      v.kind = Value::Obj;
      p_++;
      if (peek() == '}') { p_++; return v; }
      for (;;) {
        std::string k = str();
        expect(':');
        v.o[k] = value();
        if (peek() == ',') { p_++; continue; }
        expect('}');
        return v;
      }
    }
    if (c == '[') {
      v.kind = Value::Arr;
      p_++;
      if (peek() == ']') { p_++; return v; }
      for (;;) {
        v.a.push_back(value());
        if (peek() == ',') { p_++; continue; }
        expect(']');
        return v;
      }
    }
    if (c == '"') {
      v.kind = Value::Str;
      v.s = str();
      return v;
    }
    if (t_.compare(p_, 4, "true") == 0) { p_ += 4; v.kind = Value::Bool; v.b = true; return v; }
    if (t_.compare(p_, 5, "false") == 0) { p_ += 5; v.kind = Value::Bool; return v; }
    if (t_.compare(p_, 4, "null") == 0) { p_ += 4; return v; }
    size_t end = p_;
    if (t_[end] == '-') end++;
    while (end < t_.size() && t_[end] >= '0' && t_[end] <= '9') end++;
    if (end == p_) throw std::runtime_error("bad JSON value");
    v.kind = Value::Int;
    v.i = std::strtoll(t_.substr(p_, end - p_).c_str(), nullptr, 10);
    p_ = end;
    return v;
  }
};

}  // namespace json

#endif
