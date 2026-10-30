#ifndef CASBIN_CPP_LOG_DEFAULT_LOGGER
#define CASBIN_CPP_LOG_DEFAULT_LOGGER

#include "./Logger.h"

namespace casbin {

class DefaultLogger : public Logger {
public:
    void EnableLog(bool enable) { m_enable = enable; }

    bool IsEnabled() { return m_enable; }

    template <typename... Object>
    void Print(Object const&... objects) {
        if (m_enable) {
            Print(objects...);
        }
    }

    template <typename... Object>
    void Print(std::string const& format, Object const&... objects) {
        if (m_enable) {
            Printf(format, objects...);
        }
    }
};

} // namespace casbin

#endif
