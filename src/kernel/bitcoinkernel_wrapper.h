// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
#define BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H

#include <kernel/bitcoinkernel.h>

#include <iostream>
#include <memory>
#include <vector>

int verify_script(std::vector<unsigned char>& script_pubkey,
                  int64_t amount,
                  std::vector<unsigned char>& tx_to,
                  std::vector<kernel_TransactionOutput> spent_outputs,
                  unsigned int input_index,
                  unsigned int flags,
                  kernel_Error& error)
{
    auto spent_outputs_ptr = spent_outputs.size() > 0 ? spent_outputs.data() : nullptr;
    return kernel_verify_script(
        script_pubkey.data(), script_pubkey.size(),
        amount,
        tx_to.data(), tx_to.size(),
        spent_outputs_ptr, spent_outputs.size(),
        input_index,
        flags,
        &error);
}


template<typename T>
concept Log = requires(T a, const char* message) {
    { a.LogMessage(message) } -> std::same_as<void>;
};

template<Log T>
class Logger
{
private:
    struct Deleter {
        void operator()(kernel_LoggingConnection* ptr) const
        {
            kernel_logging_connection_destroy(ptr);
        }
    };

    std::unique_ptr<T> m_log;
    std::unique_ptr<kernel_LoggingConnection, Deleter> m_connection;

public:
    Logger(std::unique_ptr<T> log, kernel_LoggingOptions& logging_options, kernel_Error& error)
        : m_log{std::move(log)},
        m_connection{kernel_logging_connection_create(
              [](void* user_data, const char* message) { static_cast<T*>(user_data)->LogMessage(message); },
              m_log.get(),
              logging_options,
              &error)}
    {
    }

    Logger() = delete;
    Logger(Logger const&) = delete;
    Logger& operator=(Logger const&) = delete;

    static void EnableLogCategory(kernel_LogCategory category)
    {
        kernel_enable_log_category(kernel_LogCategory::kernel_LOG_VALIDATION);
    }

};

#endif // BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
