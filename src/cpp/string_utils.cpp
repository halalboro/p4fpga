#include "common.h"
#include "string_utils.h"
#include <cassert>
#include <cctype>

namespace SV {

static const char kSpaceChars[] = { '_', ' ', '.' };

static inline bool IsSpace(char c) {
    for (size_t i = 0; i < sizeof(kSpaceChars) / sizeof(kSpaceChars[0]); ++i) {
        if (c == kSpaceChars[i]) return true;
    }
    return false;
}

static inline bool CanAppendSnakeBar(const std::string& s) {
    return s.size() > 0 && !IsSpace(s.back());
}

cstring SnakeCase(const cstring& source) {
    std::string snake;
    std::string src = source.string();
    snake.reserve(2 * src.size());
    bool prev_is_digit = false;
    
    for (size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];
        
        // When transitioning to or from a string of digits, we want to insert '_'.
        const bool is_digit = isdigit(c) != 0;
        const bool is_digit_transition = is_digit != prev_is_digit;
        prev_is_digit = is_digit;
        
        // Convert spaces to underbars.
        if (IsSpace(c)) {
            if (CanAppendSnakeBar(snake)) snake += '_';
            continue;
        }
        
        // Convert upper case letters into '_' + lower case letter.
        if (isupper(c) || is_digit_transition) {
            if (CanAppendSnakeBar(snake)) snake += '_';
            // tolower() returns digits unchanged.
            snake += static_cast<char>(tolower(c));
            continue;
        }
        
        // Send through as-is.
        snake += c;
    }
    
    // Remove trailing underbar. There should be at most one since we never
    // output double underbars.
    if (snake.size() > 0 && snake.back() == '_') {
        snake.resize(snake.size() - 1);
    }
    
    assert(snake.size() == 0 || snake.back() != '_');
    
    return cstring(snake);
}

cstring CamelCase(const cstring& source) {
    std::string camel;
    std::string src = source.string();
    camel.reserve(src.size());
    bool capitalize_next = true;

    for (size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];
        
        // Skip spaces, but flag the next letter as start of new word.
        if (IsSpace(c)) {
            capitalize_next = true;
            continue;
        }
        
        // If flagged for capitalization, capitalize and clear flag.
        if (capitalize_next) {
            camel += static_cast<char>(toupper(c));
            capitalize_next = false;
            continue;
        }
        
        // Send through as-is.
        camel += c;
    }
    
    return cstring(camel);
}

cstring camelCase(const cstring& source) {
    std::string camel;
    std::string src = source.string();
    camel.reserve(src.size());
    bool capitalize_next = false;  // Changed from true to false for camelCase

    for (size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];
        
        // Skip spaces, but flag the next letter as start of new word.
        if (IsSpace(c)) {
            capitalize_next = true;
            continue;
        }
        
        // If flagged for capitalization, capitalize and clear flag.
        if (capitalize_next) {
            camel += static_cast<char>(toupper(c));
            capitalize_next = false;
        } else if (i == 0) {
            // First character should be lowercase for camelCase
            camel += static_cast<char>(tolower(c));
        } else {
            // Send through as-is.
            camel += c;
        }
    }
    
    return cstring(camel);
}

cstring UpperCase(const cstring& source) {
    std::string upper;
    std::string src = source.string();
    upper.reserve(src.size());

    for (size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];

        // Skip spaces
        if (IsSpace(c)) {
            continue;
        }
        
        // Convert to uppercase
        upper += static_cast<char>(toupper(c));
    }
    
    return cstring(upper);
}

cstring RemoveDot(const cstring& source) {
    std::string newstr;
    std::string src = source.string();
    newstr.reserve(src.size());

    for (size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];

        // Replace dots with dollar signs
        if (c == '.') {
            newstr += '$';
        } else {
            // Send through as-is.
            newstr += c;
        }
    }
    
    return cstring(newstr);
}

}  // namespace SV