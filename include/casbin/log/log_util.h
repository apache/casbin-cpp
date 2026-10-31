#ifndef CASBIN_CPP_LOG_LOG_UTIL
#define CASBIN_CPP_LOG_LOG_UTIL

#include "./default_logger.h"

namespace casbin {

class LogUtil {
private:
    static DefaultLogger s_logger;

public:
    // SetLogger sets the current logger.
    static void SetLogger(const DefaultLogger& l) { s_logger = l; }

    // GetLogger returns the current logger.
    static DefaultLogger GetLogger() { return s_logger; }

    // LogPrint prints the log.
    template <typename... Object>
    static void LogPrint(Object const&... objects) {
        s_logger.Print(objects...);
    }

    // LogPrintf prints the log with the format.
    template <typename... Object>
    static void LogPrintf(std::string const& format, Object const&... objects) {
        s_logger.Printf(format, objects...);
    }
};

} // namespace casbin

#endif
