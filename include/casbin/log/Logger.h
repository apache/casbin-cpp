#ifndef CASBIN_CPP_LOG_LOGGER
#define CASBIN_CPP_LOG_LOGGER

#include <string>

namespace casbin {

class Logger {
protected:
    bool m_enable;

public:
    // EnableLog controls whether print the message.
    virtual void EnableLog(bool enable) = 0;

    // IsEnabled returns if logger is enabled.
    virtual bool IsEnabled() = 0;

    // Print formats using the default formats for its operands and logs the message.
    template <typename T, typename... Object>
    void Print(T const& arg, Object const&... objects);

    // Printf formats according to a format specifier and logs the message.
    template <typename... Object>
    void Printf(std::string const& format, Object const&... objects);
};

} // namespace casbin

#endif
