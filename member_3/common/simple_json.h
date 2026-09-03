#pragma once

#include <cctype>
#include <cstdlib>
#include <istream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>

namespace ecdat {
namespace simple_json {

class Value {
public:
    enum class Type { OBJECT, STRING, NUMBER, BOOLEAN };

    static Value parse(std::istream& input) {
        std::string text((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
        Parser parser(text);
        Value value = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw std::runtime_error("Unexpected data after JSON value");
        }
        return value;
    }

    const Value& at(const std::string& key) const {
        if (type_ != Type::OBJECT) {
            throw std::runtime_error("JSON value is not an object");
        }
        const auto it = object_.find(key);
        if (it == object_.end()) {
            throw std::runtime_error("Missing JSON field: " + key);
        }
        return it->second;
    }

    const std::map<std::string, Value>& items() const {
        if (type_ != Type::OBJECT) {
            throw std::runtime_error("JSON value is not an object");
        }
        return object_;
    }

    std::string stringValue() const {
        if (type_ != Type::STRING) {
            throw std::runtime_error("JSON value is not a string");
        }
        return string_;
    }

    double numberValue() const {
        if (type_ != Type::NUMBER) {
            throw std::runtime_error("JSON value is not a number");
        }
        return number_;
    }

    bool boolValue() const {
        if (type_ != Type::BOOLEAN) {
            throw std::runtime_error("JSON value is not a boolean");
        }
        return boolean_;
    }

private:
    class Parser {
    public:
        explicit Parser(const std::string& text) : text_(text), position_(0) {}

        Value parseValue() {
            skipWhitespace();
            if (atEnd()) {
                throw std::runtime_error("Unexpected end of JSON input");
            }
            if (text_[position_] == '{') return parseObject();
            if (text_[position_] == '"') return parseString();
            if (text_[position_] == 't' || text_[position_] == 'f') return parseBoolean();
            return parseNumber();
        }

        void skipWhitespace() {
            while (!atEnd() && std::isspace(static_cast<unsigned char>(text_[position_]))) {
                ++position_;
            }
        }

        bool atEnd() const { return position_ == text_.size(); }

    private:
        Value parseObject() {
            Value result(Type::OBJECT);
            ++position_;
            skipWhitespace();
            if (!atEnd() && text_[position_] == '}') {
                ++position_;
                return result;
            }
            while (true) {
                skipWhitespace();
                Value key = parseString();
                skipWhitespace();
                expect(':');
                result.object_.emplace(key.string_, parseValue());
                skipWhitespace();
                if (!atEnd() && text_[position_] == '}') {
                    ++position_;
                    return result;
                }
                expect(',');
            }
        }

        Value parseString() {
            expect('"');
            std::string result;
            while (!atEnd() && text_[position_] != '"') {
                if (text_[position_] == '\\') {
                    ++position_;
                    if (atEnd()) throw std::runtime_error("Invalid JSON string");
                    result += text_[position_];
                } else {
                    result += text_[position_];
                }
                ++position_;
            }
            expect('"');
            Value value(Type::STRING);
            value.string_ = result;
            return value;
        }

        Value parseBoolean() {
            const bool value = text_.compare(position_, 4, "true") == 0;
            const std::size_t length = value ? 4 : 5;
            if (text_.compare(position_, length, value ? "true" : "false") != 0) {
                throw std::runtime_error("Invalid JSON boolean");
            }
            position_ += length;
            Value result(Type::BOOLEAN);
            result.boolean_ = value;
            return result;
        }

        Value parseNumber() {
            const char* start = text_.c_str() + position_;
            char* end = nullptr;
            const double value = std::strtod(start, &end);
            if (end == start) throw std::runtime_error("Invalid JSON number");
            position_ += static_cast<std::size_t>(end - start);
            Value result(Type::NUMBER);
            result.number_ = value;
            return result;
        }

        void expect(char expected) {
            if (atEnd() || text_[position_] != expected) {
                throw std::runtime_error("Invalid JSON syntax");
            }
            ++position_;
        }

        const std::string& text_;
        std::size_t position_;
    };

    explicit Value(Type type) : type_(type), number_(0.0), boolean_(false) {}

    Type type_;
    std::map<std::string, Value> object_;
    std::string string_;
    double number_;
    bool boolean_;
};

}  // namespace simple_json
}  // namespace ecdat
