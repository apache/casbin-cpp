#include "casbin/pch.h"

#ifndef LOGGER_CPP
#define LOGGER_CPP

#include "casbin/log/Logger.h"
#include "casbin/log/log_util.h"

namespace casbin {

// Print formats using the default formats for its operands and logs the message.
template <typename T, typename... Object>
void Logger::Print(T const& arg, Object const&... objects) {
    return;
}

// Printf formats according to a format specifier and logs the message.
template <typename... Object>
void Logger::Printf(std::string const& format, Object const&... objects) {
    Print(objects...);
}

DefaultLogger LogUtil::s_logger;

} // namespace casbin

#endif // LOGGER_CPP
