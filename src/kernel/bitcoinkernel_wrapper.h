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

template <typename T>
class KernelNotifications
{
private:
    kernel_NotificationInterfaceCallbacks MakeCallbacks()
    {
        return kernel_NotificationInterfaceCallbacks{
            .user_data = this,
            .block_tip = [](void* user_data, kernel_SynchronizationState state, kernel_BlockIndex* index) {
                static_cast<T*>(user_data)->BlockTipHandler(state, index);
            },
            .header_tip = [](void* user_data, kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {
                static_cast<T*>(user_data)->HeaderTipHandler(state, height, timestamp, presync);
            },
            .progress = [](void* user_data, const char* title, int progress_percent, bool resume_possible) {
                static_cast<T*>(user_data)->ProgressHandler(title, progress_percent, resume_possible);
            },
            .warning_set = [](void* user_data, kernel_Warning warning, const char* message) {
                static_cast<T*>(user_data)->WarningSetHandler(warning, message);
            },
            .warning_unset = [](void* user_data, kernel_Warning warning) { static_cast<T*>(user_data)->WarningUnsetHandler(warning); },
            .flush_error = [](void* user_data, const char* error) { static_cast<T*>(user_data)->FlushErrorHandler(error); },
            .fatal_error = [](void* user_data, const char* error) { static_cast<T*>(user_data)->FatalErrorHandler(error); },
        };
    }

public:
    virtual ~KernelNotifications() = default;

    virtual void BlockTipHandler(kernel_SynchronizationState state, kernel_BlockIndex* index) {}

    virtual void HeaderTipHandler(kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {}

    virtual void ProgressHandler(const char* title, int progress_percent, bool resume_possible) {}

    virtual void WarningSetHandler(kernel_Warning warning, const char* message) {}

    virtual void WarningUnsetHandler(kernel_Warning warning) {}

    virtual void FlushErrorHandler(const char* error) {}

    virtual void FatalErrorHandler(const char* error) {}

    friend class ContextOptions;
};

class ChainParams
{
private:
    struct Deleter {
        void operator()(const kernel_ChainParameters* ptr) const
        {
            kernel_chain_parameters_destroy(ptr);
        }
    };

    std::unique_ptr<const kernel_ChainParameters, Deleter> m_chain_params;

public:
    ChainParams(kernel_ChainType chain_type) : m_chain_params{kernel_chain_parameters_create(chain_type)} {}

    ChainParams() = delete;

    friend class ContextOptions;
};

class ContextOptions
{
private:
    struct Deleter {
        void operator()(kernel_ContextOptions* ptr) const
        {
            kernel_context_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_ContextOptions, Deleter> m_options;

public:
    ContextOptions() : m_options{kernel_context_options_create()} {}

    void SetChainParams(ChainParams& chain_params, kernel_Error& error)
    {
        kernel_context_options_set(
            m_options.get(),
            kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION,
            reinterpret_cast<const void*>(chain_params.m_chain_params.get()),
            &error);
    }

    template <typename T>
    void SetNotificationCallbacks(KernelNotifications<T>& notifications, kernel_Error& error)
    {
        auto callbacks = notifications.MakeCallbacks();
        kernel_context_options_set(
            m_options.get(),
            kernel_ContextOptionType::kernel_NOTIFICATION_INTERFACE_CALLBACKS_OPTION,
            &callbacks,
            &error);
    }

    friend class Context;
};

class Context
{
private:
    struct Deleter {
        void operator()(kernel_Context* ptr) const
        {
            kernel_context_destroy(ptr);
        }
    };

public:
    std::unique_ptr<kernel_Context, Deleter> m_context;

    Context(ContextOptions& opts, kernel_Error& error)
        : m_context{kernel_context_create(opts.m_options.get(), &error)}
    {
    }

    Context(kernel_Error& error)
        : m_context{kernel_context_create(ContextOptions{}.m_options.get(), &error)}
    {
    }

    Context() = delete;
};

class ChainstateManagerOptions
{
private:
    struct Deleter {
        void operator()(kernel_ChainstateManagerOptions* ptr) const
        {
            kernel_chainstate_manager_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_ChainstateManagerOptions, Deleter> m_options;

public:
    ChainstateManagerOptions(Context& context, const std::string& data_dir, kernel_Error& error)
        : m_options{kernel_chainstate_manager_options_create(context.m_context.get(), data_dir.c_str(), &error)}
    {
    }

    ChainstateManagerOptions() = delete;

    friend class ChainMan;
};

class BlockManagerOptions
{
private:
    struct Deleter {
        void operator()(kernel_BlockManagerOptions* ptr) const
        {
            kernel_block_manager_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_BlockManagerOptions, Deleter> m_options;

public:
    BlockManagerOptions(Context& context, const std::string& data_dir, kernel_Error& error)
        : m_options{kernel_block_manager_options_create(context.m_context.get(), data_dir.c_str(), &error)}
    {
    }

    BlockManagerOptions() = delete;

    friend class ChainMan;
};

class ChainstateLoadOptions
{
private:
    struct Deleter {
        void operator()(kernel_ChainstateLoadOptions* ptr) const
        {
            kernel_chainstate_load_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_ChainstateLoadOptions, Deleter> m_options;

public:
    ChainstateLoadOptions()
        : m_options{kernel_chainstate_load_options_create()}
    {
    }

    friend class ChainMan;
};

class ChainMan
{
private:
    kernel_ChainstateManager* m_chainman;
    Context& m_context;

public:
    ChainMan(Context& context, ChainstateManagerOptions& chainman_opts, BlockManagerOptions& blockman_opts, kernel_Error& error)
        : m_chainman{kernel_chainstate_manager_create(chainman_opts.m_options.get(), blockman_opts.m_options.get(), context.m_context.get(), &error)},
          m_context{context}
    {
    }

    ChainMan() = delete;
    ChainMan(const ChainMan&) = delete;
    ChainMan& operator=(const ChainMan&) = delete;

    void LoadChainstate(ChainstateLoadOptions& chainstate_load_opts, kernel_Error& error)
    {
        kernel_chainstate_manager_load_chainstate(m_context.m_context.get(), chainstate_load_opts.m_options.get(), m_chainman, &error);
    }

    ~ChainMan()
    {
        kernel_chainstate_manager_destroy(m_chainman, m_context.m_context.get());
    }
};

#endif // BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
