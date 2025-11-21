#ifndef P4FPGA_COMMON_H
#define P4FPGA_COMMON_H

#include "ir/ir.h"
#include "ir/visitor.h"
#include "lib/cstring.h"
#include "lib/error.h"
#include "lib/nullstream.h"
#include "lib/sourceCodeBuilder.h"
#include "lib/log.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"
#include "frontends/common/options.h"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <cstdarg>

namespace SV {
    using namespace P4;
    
    // Import commonly used IR types
    using P4::IR::Node;
    using P4::IR::Type;
    using P4::IR::Type_Bits;
    using P4::IR::Type_Boolean;
    using P4::IR::Type_Name;
    using P4::IR::Type_StructLike;
    using P4::IR::Type_Struct;
    using P4::IR::Type_Header;
    using P4::IR::Type_Typedef;
    using P4::IR::P4Program;
    using P4::IR::ToplevelBlock;
    using P4::IR::P4Control;
    using P4::IR::P4Parser;
    using P4::IR::P4Table;
    using P4::IR::P4Action;
    using P4::IR::ParserBlock;
    using P4::IR::ControlBlock;
    using P4::IR::Expression;
    using P4::IR::Statement;
    using P4::IR::BlockStatement;
    using P4::IR::IfStatement;
    using P4::IR::SwitchStatement;
    using P4::IR::Member;
    using P4::IR::Constant;
    using P4::IR::PathExpression;
    using P4::IR::MethodCallExpression;
    using P4::IR::MethodCallStatement;
    using P4::IR::AssignmentStatement;
    using P4::IR::Declaration;
    using P4::IR::Parameter;
    using P4::IR::ParserState;
    using P4::IR::SelectExpression;
    using P4::IR::KeyElement;
    using P4::IR::ActionListElement;
    
    // Common P4 types
    using P4::cstring;
    using P4::TypeMap;
    using P4::ReferenceMap;
    using P4::CompilerOptions;
    using P4::Inspector;
    
    // Utility types
    using Util::SourceCodeBuilder;
    typedef Util::SourceCodeBuilder CodeBuilder;
    
    // Error handling
    using P4::error;
    using P4::warning;
    
    struct ExtractedParserState {
        cstring name;
        bool isStart;
        bool isAccept;
        std::vector<cstring> extractedHeaders;  // Names of headers to extract
        std::map<cstring, cstring> transitions;  // condition -> next_state
        
        ExtractedParserState(cstring n) : name(n), isStart(false), isAccept(false) {}
    };
    
    extern std::map<P4::cstring, std::vector<ExtractedParserState>> g_extractedParserStates;
    extern bool g_verbose;

    // Forward declarations for SV backend classes
    class SVProgram;
    class SVCodeGen;
    class SVParser;
    class SVControl;
    class SVDeparser;
    class SVTable;
    class SVAction;
    class SVOptions;
    
    // Base class for FPGA objects
    class FPGAObject {
    public:
        virtual ~FPGAObject() {}
    };
    
    // Parser state representation
    class SVParseState {
    public:
        cstring name;
        std::vector<const IR::Expression*> extracts;
        std::map<cstring, cstring> transitions;
        
        SVParseState(const IR::ParserState* state) {
            if (state) {
                name = state->name;
            } else {
                name = cstring("INVALID");
                P4::warning("SVParseState created with null state");
            }
        }
    };
    
    // Helper function for formatted output (since appendFormat doesn't exist)
    inline void appendFormat(CodeBuilder* builder, const char* format, ...) {
        char buffer[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        builder->append(buffer);
    }
    
    // Helper to convert cstring to std::string safely
    inline std::string str(const cstring& cs) {
        return cs.isNull() ? "" : cs.c_str();
    }
    
    // Logging macros (if not already defined)
    #ifndef LOG1
    #define LOG1(x) LOG4(x)
    #endif
    #ifndef LOG2
    #define LOG2(x) LOG4(x)
    #endif
    #ifndef LOG3
    #define LOG3(x) LOG4(x)
    #endif
    
}  // namespace SV

#endif