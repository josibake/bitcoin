// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <kernel/chainparams.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <kernel/warning.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <undo.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/task_runner.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context kernel_context_static{};

namespace {

// These tags are used to guard against void* types pointing to unexpected data
constexpr uint64_t KERNEL_CHAIN_PARAMS_TAG{0};
constexpr uint64_t KERNEL_NOTIFICATIONS_TAG{1};
constexpr uint64_t KERNEL_TASK_RUNNER_TAG{2};
constexpr uint64_t KERNEL_MEMPOOL_OPTIONS_TAG{3};

/** A class that deserializes a single CTransaction one time. */
class TxInputStream
{
private:
    const unsigned char* m_data;
    size_t m_remaining;

public:
    TxInputStream(const unsigned char* txTo, size_t txToLen) : m_data{txTo},
                                                               m_remaining{txToLen}
    {
    }

    void read(Span<std::byte> dst)
    {
        if (dst.size() > m_remaining) {
            throw std::ios_base::failure(std::string(__func__) + ": end of data");
        }

        if (dst.data() == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad destination buffer");
        }

        if (m_data == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad source buffer");
        }

        memcpy(dst.data(), m_data, dst.size());
        m_remaining -= dst.size();
        m_data += dst.size();
    }

    template <typename T>
    TxInputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }
};

/** Check that all specified flags are part of the libbitcoinkernel interface. */
bool verify_flags(unsigned int flags)
{
    return (flags & ~(kernel_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

std::string log_level_to_string(const kernel_LogLevel level)
{
    switch (level) {
    case kernel_LogLevel::kernel_LOG_INFO: {
        return "info";
    }
    case kernel_LogLevel::kernel_LOG_DEBUG: {
        return "debug";
    }
    case kernel_LogLevel::kernel_LOG_TRACE: {
        return "trace";
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::string log_category_to_string(const kernel_LogCategory category)
{
    switch (category) {
    case kernel_LogCategory::kernel_LOG_BENCH: {
        return "bench";
    }
    case kernel_LogCategory::kernel_LOG_BLOCKSTORAGE: {
        return "blockstorage";
    }
    case kernel_LogCategory::kernel_LOG_COINDB: {
        return "coindb";
    }
    case kernel_LogCategory::kernel_LOG_LEVELDB: {
        return "leveldb";
    }
    case kernel_LogCategory::kernel_LOG_LOCK: {
        return "lock";
    }
    case kernel_LogCategory::kernel_LOG_MEMPOOL: {
        return "mempool";
    }
    case kernel_LogCategory::kernel_LOG_PRUNE: {
        return "prune";
    }
    case kernel_LogCategory::kernel_LOG_RAND: {
        return "rand";
    }
    case kernel_LogCategory::kernel_LOG_REINDEX: {
        return "reindex";
    }
    case kernel_LogCategory::kernel_LOG_VALIDATION: {
        return "validation";
    }
    case kernel_LogCategory::kernel_LOG_KERNEL: {
        return "kernel";
    }
    case kernel_LogCategory::kernel_LOG_ALL: {
        return "all";
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

class KernelChainParams
{
    uint64_t m_tag;

public:
    std::unique_ptr<const CChainParams> m_chainparams;

    KernelChainParams(std::unique_ptr<const CChainParams> chainparams)
        : m_tag{KERNEL_CHAIN_PARAMS_TAG},
          m_chainparams{std::move(chainparams)}
    {
    }

    bool IsValid() const
    {
        return m_tag == KERNEL_CHAIN_PARAMS_TAG;
    }
};

class KernelMempoolOptions
{
    uint64_t m_tag;

public:
    CTxMemPool::Options m_mempool_options;

    KernelMempoolOptions()
        : m_tag{KERNEL_MEMPOOL_OPTIONS_TAG},
          m_mempool_options{CTxMemPool::Options{}}
    {
    }

    bool IsValid() const
    {
        return m_tag == KERNEL_MEMPOOL_OPTIONS_TAG;
    }
};

kernel_SynchronizationState cast_state(SynchronizationState state)
{
    switch (state) {
    case SynchronizationState::INIT_REINDEX:
        return kernel_SynchronizationState::kernel_INIT_REINDEX;
    case SynchronizationState::INIT_DOWNLOAD:
        return kernel_SynchronizationState::kernel_INIT_DOWNLOAD;
    case SynchronizationState::POST_INIT:
        return kernel_SynchronizationState::kernel_POST_INIT;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

kernel_Warning cast_kernel_warning(kernel::Warning warning)
{
    switch (warning) {
    case kernel::Warning::UNKNOWN_NEW_RULES_ACTIVATED:
        return kernel_Warning::kernel_LARGE_WORK_INVALID_CHAIN;
    case kernel::Warning::LARGE_WORK_INVALID_CHAIN:
        return kernel_Warning::kernel_LARGE_WORK_INVALID_CHAIN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

class KernelNotifications : public kernel::Notifications
{
private:
    uint64_t m_tag;
    kernel_NotificationInterfaceCallbacks m_cbs;

public:
    KernelNotifications(kernel_NotificationInterfaceCallbacks cbs)
        : m_tag{KERNEL_NOTIFICATIONS_TAG},
          m_cbs{cbs}
    {
    }

    kernel::InterruptResult blockTip(SynchronizationState state, CBlockIndex& index) override
    {
        if (m_cbs.block_tip) m_cbs.block_tip(m_cbs.user_data, cast_state(state), reinterpret_cast<kernel_BlockIndex*>(&index));
        return {};
    }
    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs.header_tip) m_cbs.header_tip(m_cbs.user_data, cast_state(state), height, timestamp, presync);
    }
    void warningSet(kernel::Warning id, const bilingual_str& message) override
    {
        if (m_cbs.warning_set) m_cbs.warning_set(m_cbs.user_data, cast_kernel_warning(id), message.original.c_str());
    }
    void warningUnset(kernel::Warning id) override
    {
        if (m_cbs.warning_unset) m_cbs.warning_unset(m_cbs.user_data, cast_kernel_warning(id));
    }
    void flushError(const bilingual_str& message) override
    {
        if (m_cbs.flush_error) m_cbs.flush_error(m_cbs.user_data, message.original.c_str());
    }
    void fatalError(const bilingual_str& message) override
    {
        if (m_cbs.fatal_error) m_cbs.fatal_error(m_cbs.user_data, message.original.c_str());
    }

    bool IsValid() const
    {
        return m_tag == KERNEL_NOTIFICATIONS_TAG;
    }
};

class TaskRunner : public util::TaskRunnerInterface
{
private:
    uint64_t m_tag;
    kernel_TaskRunnerCallbacks m_cbs;

public:
    TaskRunner(kernel_TaskRunnerCallbacks tr_cbs)
        : m_tag{KERNEL_TASK_RUNNER_TAG},
          m_cbs{tr_cbs}
    {
    }

    void insert(std::function<void()> func) override
    {
        if (m_cbs.insert) {
            // prevent the event from being deleted when it goes out of scope
            // here, it is the caller's responsibility to correctly call
            // kernel_execute_event_and_destroy to process it, preventing a memory leak.
            auto heap_func = new std::function<void()>(func);

            m_cbs.insert(m_cbs.user_data, reinterpret_cast<kernel_ValidationEvent*>(heap_func));
        }
    }

    void flush() override
    {
        if (m_cbs.flush) m_cbs.flush(m_cbs.user_data);
    }

    size_t size() override
    {
        if (m_cbs.size) return m_cbs.size(m_cbs.user_data);
        return 0;
    }

    bool IsValid() const
    {
        return m_tag == KERNEL_TASK_RUNNER_TAG;
    }
};

struct ContextOptions {
    std::unique_ptr<const KernelNotifications> m_notifications;
    std::unique_ptr<const CChainParams> m_chainparams;
    std::unique_ptr<TaskRunner> m_task_runner;
    std::unique_ptr<const CTxMemPool::Options> m_mempool_options;
};

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<ValidationSignals> m_signals;

    std::unique_ptr<KernelNotifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<const CChainParams> m_chainparams;

    std::unique_ptr<CTxMemPool> m_mempool;

    Context(const ContextOptions* options, bool& sane)
        : m_context{std::make_unique<kernel::Context>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()}
    {
        if (options && options->m_notifications) {
            m_notifications = std::make_unique<KernelNotifications>(*options->m_notifications);
        } else {
            m_notifications = std::make_unique<KernelNotifications>(kernel_NotificationInterfaceCallbacks{
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr});
        }

        if (options && options->m_chainparams) {
            m_chainparams = std::make_unique<const CChainParams>(*options->m_chainparams);
        } else {
            m_chainparams = CChainParams::Main();
        }

        if (options && options->m_task_runner) {
            m_signals = std::make_unique<ValidationSignals>(std::make_unique<TaskRunner>(*options->m_task_runner));
        } else {
            m_signals = nullptr;
        }

        if (options && options->m_mempool_options) {
            bilingual_str mempool_err;
            m_mempool = std::make_unique<CTxMemPool>(*options->m_mempool_options, mempool_err);
            if (!mempool_err.empty()) {
                LogError("Failed to construct a chainstate manager: %s", mempool_err.original);
                sane = false;
            }
        } else {
            m_mempool = nullptr;
        }

        if (!kernel::SanityChecks(*m_context)) {
            sane = false;
        }
    }
};

class KernelValidationInterface final : public CValidationInterface
{
public:
    const kernel_ValidationInterfaceCallbacks m_cbs;

    explicit KernelValidationInterface(const kernel_ValidationInterfaceCallbacks vi_cbs) : m_cbs{vi_cbs} {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override
    {
        if (m_cbs.block_checked) {
            m_cbs.block_checked(m_cbs.user_data,
                                reinterpret_cast<const kernel_BlockPointer*>(&block),
                                reinterpret_cast<const kernel_BlockValidationState*>(&stateIn));
        }
    }
};

const ContextOptions* cast_const_context_options(const kernel_ContextOptions* options)
{
    assert(options);
    return reinterpret_cast<const ContextOptions*>(options);
}

ContextOptions* cast_context_options(kernel_ContextOptions* options)
{
    assert(options);
    return reinterpret_cast<ContextOptions*>(options);
}

const KernelChainParams* cast_const_chain_params(const kernel_ChainParameters* chain_params)
{
    assert(chain_params);
    return reinterpret_cast<const KernelChainParams*>(chain_params);
}

const KernelMempoolOptions* cast_const_mempool_options(const kernel_MempoolOptions* mempool)
{
    assert(mempool);
    return reinterpret_cast<const KernelMempoolOptions*>(mempool);
}

const KernelNotifications* cast_const_notifications(const kernel_Notifications* notifications)
{
    assert(notifications);
    return reinterpret_cast<const KernelNotifications*>(notifications);
}

Context* cast_context(kernel_Context* context)
{
    assert(context);
    return reinterpret_cast<Context*>(context);
}

const Context* cast_const_context(const kernel_Context* context)
{
    assert(context);
    return reinterpret_cast<const Context*>(context);
}

ChainstateManager::Options* cast_chainstate_manager_options(kernel_ChainstateManagerOptions* options)
{
    assert(options);
    return reinterpret_cast<ChainstateManager::Options*>(options);
}

node::BlockManager::Options* cast_block_manager_options(kernel_BlockManagerOptions* options)
{
    assert(options);
    return reinterpret_cast<node::BlockManager::Options*>(options);
}

ChainstateManager* cast_chainstate_manager(kernel_ChainstateManager* chainman)
{
    assert(chainman);
    return reinterpret_cast<ChainstateManager*>(chainman);
}

node::ChainstateLoadOptions* cast_chainstate_load_options(kernel_ChainstateLoadOptions* options)
{
    assert(options);
    return reinterpret_cast<node::ChainstateLoadOptions*>(options);
}

std::shared_ptr<CBlock>* cast_cblocksharedpointer(kernel_Block* block)
{
    assert(block);
    return reinterpret_cast<std::shared_ptr<CBlock>*>(block);
}

std::shared_ptr<KernelValidationInterface>* cast_validation_interface(kernel_ValidationInterface* interface)
{
    assert(interface);
    return reinterpret_cast<std::shared_ptr<KernelValidationInterface>*>(interface);
}

std::function<void()>* cast_validation_event(kernel_ValidationEvent* event)
{
    assert(event);
    return reinterpret_cast<std::function<void()>*>(event);
}

const TaskRunner* cast_task_runner(kernel_TaskRunner* task_runner)
{
    assert(task_runner);
    return reinterpret_cast<const TaskRunner*>(task_runner);
}

const BlockValidationState* cast_block_validation_state(const kernel_BlockValidationState* block_validation_state)
{
    assert(block_validation_state);
    return reinterpret_cast<const BlockValidationState*>(block_validation_state);
}

const CBlock* cast_const_cblock(const kernel_BlockPointer* block)
{
    assert(block);
    return reinterpret_cast<const CBlock*>(block);
}

CBlockIndex* cast_block_index(kernel_BlockIndex* index)
{
    assert(index);
    return reinterpret_cast<CBlockIndex*>(index);
}

CBlockUndo* cast_block_undo(kernel_BlockUndo* undo)
{
    assert(undo);
    return reinterpret_cast<CBlockUndo*>(undo);
}

static CCoinsViewCursor* cast_coins_view_cursor(kernel_CoinsViewCursor* cursor)
{
    assert(cursor);
    return reinterpret_cast<CCoinsViewCursor*>(cursor);
}

CBlockHeader* cast_block_header(kernel_BlockHeader* header)
{
    assert(header);
    return reinterpret_cast<CBlockHeader*>(header);
}

CTransactionRef* cast_transaction_ref(kernel_Transaction* transaction)
{
    assert(transaction);
    return reinterpret_cast<CTransactionRef*>(transaction);
}

} // namespace

bool kernel_verify_script(const unsigned char* script_pubkey, size_t script_pubkey_len,
                         const int64_t amount_,
                         const unsigned char* tx_to, size_t tx_to_len,
                         const kernel_TransactionOutput* spent_outputs_, size_t spent_outputs_len,
                         const unsigned int input_index,
                         const unsigned int flags,
                         kernel_ScriptVerifyStatus* status)
{
    const CAmount amount{amount_};

    if (!verify_flags(flags)) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS;
        return false;
    }

    if (!is_valid_flag_combination(flags)) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION;
        return false;
    }

    if (flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT && spent_outputs_ == nullptr) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED;
        return false;
    }

    try {
        TxInputStream stream{tx_to, tx_to_len};
        CTransaction tx{deserialize, TX_WITH_WITNESS, stream};

        std::vector<CTxOut> spent_outputs;
        if (spent_outputs_ != nullptr) {
            if (spent_outputs_len != tx.vin.size()) {
                if (status) *status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_MISMATCH;
                return false;
            }
            spent_outputs.reserve(spent_outputs_len);
            for (size_t i = 0; i < spent_outputs_len; i++) {
                CScript spk{CScript(spent_outputs_[i].script_pubkey, spent_outputs_[i].script_pubkey + spent_outputs_[i].script_pubkey_len)};
                const CAmount& value{spent_outputs_[i].value};
                CTxOut tx_out{CTxOut(value, spk)};
                spent_outputs.push_back(tx_out);
            }
        }

        if (input_index >= tx.vin.size()) {
            if (status) *status = kernel_SCRIPT_VERIFY_ERROR_TX_INPUT_INDEX;
            return false;
        }
        if (GetSerializeSize(TX_WITH_WITNESS(tx)) != tx_to_len) {
            if (status) *status = kernel_SCRIPT_VERIFY_ERROR_TX_SIZE_MISMATCH;
            return false;
        }

        PrecomputedTransactionData txdata{tx};

        if (spent_outputs_ != nullptr && flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT) {
            txdata.Init(tx, std::move(spent_outputs));
        }

        return VerifyScript(tx.vin[input_index].scriptSig,
                            CScript(script_pubkey,
                                    script_pubkey + script_pubkey_len),
                            &tx.vin[input_index].scriptWitness,
                            flags,
                            TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                            nullptr);
    } catch (const std::exception&) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_TX_DESERIALIZE;
        return false;
    }
}

bool kernel_add_log_level_category(const kernel_LogCategory category, const kernel_LogLevel level_)
{
    const auto level{log_level_to_string(level_)};
    if (category == kernel_LogCategory::kernel_LOG_ALL) {
        return LogInstance().SetLogLevel(level);
    }

    return LogInstance().SetCategoryLogLevel(log_category_to_string(category), level);
}

bool kernel_enable_log_category(const kernel_LogCategory category)
{
    return LogInstance().EnableCategory(log_category_to_string(category));
}

bool kernel_disable_log_category(const kernel_LogCategory category)
{
    return LogInstance().DisableCategory(log_category_to_string(category));
}

void kernel_disable_logging()
{
    LogInstance().DisableLogging();
}

kernel_LoggingConnection* kernel_logging_connection_create(kernel_LogCallback callback,
                                                           void* user_data,
                                                           const kernel_LoggingOptions options)
{
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback(user_data, str.c_str()); })};

    try {
        // Only start logging if we just added the connection.
        if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
            LogError("Logger start failed.\n");
            LogInstance().DeleteCallback(connection);
            return nullptr;
        }
    } catch (std::exception& e) {
        LogError("Logger start failed.\n");
        LogInstance().DeleteCallback(connection);
        return nullptr;
    }

    LogDebug(BCLog::KERNEL, "Logger connected.\n");

    auto heap_connection{new std::list<std::function<void(const std::string&)>>::iterator(connection)};
    return reinterpret_cast<kernel_LoggingConnection*>(heap_connection);
}

void kernel_logging_connection_destroy(kernel_LoggingConnection* connection_)
{
    auto connection{reinterpret_cast<std::list<std::function<void(const std::string&)>>::iterator*>(connection_)};
    if (!connection) {
        return;
    }

    LogDebug(BCLog::KERNEL, "Logger disconnected.\n");
    LogInstance().DeleteCallback(*connection);
    delete connection;

    // We are not buffering if we have a connection, so check that it is not the
    // last available connection.
    if (!LogInstance().Enabled()) {
        LogInstance().DisconnectTestLogger();
    }
}

const kernel_ChainParameters* kernel_chain_parameters_create(const kernel_ChainType chain_type)
{
    switch (chain_type) {
    case kernel_ChainType::kernel_CHAIN_TYPE_MAINNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(new KernelChainParams(CChainParams::Main()));
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_TESTNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(new KernelChainParams(CChainParams::TestNet()));
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_SIGNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(new KernelChainParams(CChainParams::SigNet({})));
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_REGTEST: {
        return reinterpret_cast<const kernel_ChainParameters*>(new KernelChainParams(CChainParams::RegTest({})));
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

void kernel_chain_parameters_destroy(const kernel_ChainParameters* chain_parameters)
{
    if (chain_parameters) {
        delete cast_const_chain_params(chain_parameters);
    }
}

kernel_Notifications* kernel_notifications_create(kernel_NotificationInterfaceCallbacks callbacks)
{
    return reinterpret_cast<kernel_Notifications*>(new KernelNotifications{callbacks});
}

void kernel_notifications_destroy(const kernel_Notifications* notifications)
{
    if (notifications) {
        delete cast_const_notifications(notifications);
    }
}

kernel_MempoolOptions* kernel_mempool_options_create()
{
    return reinterpret_cast<kernel_MempoolOptions*>(new KernelMempoolOptions{});
}

void kernel_mempool_options_destroy(const kernel_MempoolOptions* mempool_options)
{
    if (mempool_options) {
        delete cast_const_mempool_options(mempool_options);
    }
}

kernel_ContextOptions* kernel_context_options_create()
{
    return reinterpret_cast<kernel_ContextOptions*>(new ContextOptions{});
}

bool kernel_context_options_set(kernel_ContextOptions* options_, const kernel_ContextOptionType n_option, const void* value)
{
    auto options{cast_context_options(options_)};
    switch (n_option) {
    case kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION: {
        auto chain_params{reinterpret_cast<const KernelChainParams*>(value)};
        if (!chain_params->IsValid()) {
            LogError("Selected kernel notifications context option, but the value is not a valid chain params struct.\n");
            return false;
        }
        // Copy the chainparams, so the caller can free it again
        options->m_chainparams = std::make_unique<const CChainParams>(*chain_params->m_chainparams);
        return true;
    }
    case kernel_ContextOptionType::kernel_NOTIFICATIONS_OPTION: {
        auto notifications{reinterpret_cast<const KernelNotifications*>(value)};
        if (!notifications->IsValid()) {
            LogError("Selected kernel notifications context option, but the value is not a valid kernel notifications struct.\n");
            return false;
        }
        // This copies the data, so the caller can free it again.
        options->m_notifications = std::make_unique<KernelNotifications>(*notifications);
        return true;
    }
    case kernel_ContextOptionType::kernel_TASK_RUNNER_OPTION: {
        auto task_runner{reinterpret_cast<const TaskRunner*>(value)};
        if (!task_runner->IsValid()) {
            LogError("Selected kernel task runner context option, but the value is not a valid kernel task runner struct.\n");
            return false;
        }
        // Copy the task runner, so the caller can free it again.
        options->m_task_runner = std::make_unique<TaskRunner>(*task_runner);
        return true;
    }
    case kernel_ContextOptionType::kernel_MEMPOOL_OPTION: {
        auto mempool_opts{reinterpret_cast<const KernelMempoolOptions*>(value)};
        if (!mempool_opts->IsValid()) {
            LogError("Selected mempool option context option, but the value is not a valid mempool options struct.\n");
            return false;
        }
        options->m_mempool_options = std::make_unique<const CTxMemPool::Options>(mempool_opts->m_mempool_options);
        return true;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

void kernel_context_options_destroy(kernel_ContextOptions* options)
{
    if (options) {
        delete cast_context_options(options);
    }
}

kernel_Context* kernel_context_create(const kernel_ContextOptions* options_)
{
    auto options{cast_const_context_options(options_)};
    bool sane{true};
    auto context{new Context{options, sane}};
    if (!sane) {
        LogError("Kernel context sanity check failed.\n");
        delete context;
        return nullptr;
    }
    return reinterpret_cast<kernel_Context*>(context);
}

bool kernel_context_interrupt(kernel_Context* context_)
{
    auto& context{*cast_context(context_)};
    return (*context.m_interrupt)();
}

void kernel_context_destroy(kernel_Context* context)
{
    if (context) {
        delete cast_context(context);
    }
}

kernel_TaskRunner* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_task_runner_create(kernel_TaskRunnerCallbacks callbacks)
{
    auto runner{new TaskRunner{callbacks}};
    runner->IsValid();
    return reinterpret_cast<kernel_TaskRunner*>(runner);
}

void kernel_task_runner_destroy(kernel_TaskRunner* task_runner)
{
    if (task_runner) {
        delete cast_task_runner(task_runner);
    }
}

kernel_ValidationInterface* kernel_validation_interface_create(kernel_ValidationInterfaceCallbacks vi_cbs)
{
    return reinterpret_cast<kernel_ValidationInterface*>(new std::shared_ptr<KernelValidationInterface>(new KernelValidationInterface(vi_cbs)));
}

bool kernel_validation_interface_register(kernel_Context* context_, kernel_ValidationInterface* validation_interface_)
{
    auto context{cast_context(context_)};
    auto validation_interface{cast_validation_interface(validation_interface_)};
    if (!context->m_signals) {
        LogError("Cannot register validation interface with context that has no validation signals.\n");
        return false;
    }
    context->m_signals->RegisterSharedValidationInterface(*validation_interface);
    return true;
}

bool kernel_validation_interface_unregister(kernel_Context* context_, kernel_ValidationInterface* validation_interface_)
{
    auto context{cast_context(context_)};
    auto validation_interface{cast_validation_interface(validation_interface_)};
    if (!context->m_signals) {
        LogError("Cannot de-register validation interface with context that has no validation signals.\n");
        return false;
    }
    context->m_signals->SyncWithValidationInterfaceQueue();
    context->m_signals->FlushBackgroundCallbacks();
    context->m_signals->UnregisterSharedValidationInterface(*validation_interface);
    return true;
}

void kernel_validation_interface_destroy(kernel_ValidationInterface* validation_interface)
{
    if (validation_interface) {
        delete cast_validation_interface(validation_interface);
    }
}

void kernel_execute_event_and_destroy(kernel_ValidationEvent* event)
{
    std::function<void()>* func = cast_validation_event(event);
    try {
        (*func)();
        delete func;
    } catch (const std::exception& e) {
        LogError("Failed to execute event: %s\n", std::string{e.what()});
        if (func) delete func;
    }
}

kernel_ValidationMode kernel_get_validation_mode_from_block_validation_state(const kernel_BlockValidationState* block_validation_state_)
{
    auto& block_validation_state = *cast_block_validation_state(block_validation_state_);
    if (block_validation_state.IsValid()) return kernel_ValidationMode::kernel_VALIDATION_STATE_VALID;
    if (block_validation_state.IsInvalid()) return kernel_ValidationMode::kernel_VALIDATION_STATE_INVALID;
    return kernel_ValidationMode::kernel_VALIDATION_STATE_ERROR;
}

kernel_BlockValidationResult kernel_get_block_validation_result_from_block_validation_state(const kernel_BlockValidationState* block_validation_state_)
{
    auto& block_validation_state = *cast_block_validation_state(block_validation_state_);
    switch (block_validation_state.GetResult()) {
    case BlockValidationResult::BLOCK_RESULT_UNSET:
        return kernel_BlockValidationResult::kernel_BLOCK_RESULT_UNSET;
    case BlockValidationResult::BLOCK_CONSENSUS:
        return kernel_BlockValidationResult::kernel_BLOCK_CONSENSUS;
    case BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE:
        return kernel_BlockValidationResult::kernel_BLOCK_RECENT_CONSENSUS_CHANGE;
    case BlockValidationResult::BLOCK_CACHED_INVALID:
        return kernel_BlockValidationResult::kernel_BLOCK_CACHED_INVALID;
    case BlockValidationResult::BLOCK_INVALID_HEADER:
        return kernel_BlockValidationResult::kernel_BLOCK_INVALID_HEADER;
    case BlockValidationResult::BLOCK_MUTATED:
        return kernel_BlockValidationResult::kernel_BLOCK_MUTATED;
    case BlockValidationResult::BLOCK_MISSING_PREV:
        return kernel_BlockValidationResult::kernel_BLOCK_MISSING_PREV;
    case BlockValidationResult::BLOCK_INVALID_PREV:
        return kernel_BlockValidationResult::kernel_BLOCK_INVALID_PREV;
    case BlockValidationResult::BLOCK_TIME_FUTURE:
        return kernel_BlockValidationResult::kernel_BLOCK_TIME_FUTURE;
    case BlockValidationResult::BLOCK_CHECKPOINT:
        return kernel_BlockValidationResult::kernel_BLOCK_CHECKPOINT;
    case BlockValidationResult::BLOCK_HEADER_LOW_WORK:
        return kernel_BlockValidationResult::kernel_BLOCK_HEADER_LOW_WORK;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

kernel_ChainstateManagerOptions* kernel_chainstate_manager_options_create(const kernel_Context* context_, const char* data_dir)
{
    try {
        fs::path abs_data_dir{fs::absolute(fs::PathFromString(data_dir))};
        fs::create_directories(abs_data_dir);
        auto context{cast_const_context(context_)};
        return reinterpret_cast<kernel_ChainstateManagerOptions*>(new ChainstateManager::Options{
            .chainparams = *context->m_chainparams,
            .datadir = abs_data_dir,
            .notifications = *context->m_notifications,
            .signals = context->m_signals.get()});
    } catch (const std::exception& e) {
        LogError("Failed to create chainstate manager options: %s\n", e.what());
        return nullptr;
    }
}

void kernel_chainstate_manager_options_destroy(kernel_ChainstateManagerOptions* options)
{
    if (options) {
        delete cast_chainstate_manager_options(options);
    }
}

kernel_BlockManagerOptions* kernel_block_manager_options_create(const kernel_Context* context_, const char* blocks_dir)
{
    try {
        fs::path abs_blocks_dir{fs::absolute(fs::PathFromString(blocks_dir))};
        fs::create_directories(abs_blocks_dir);
        auto context{cast_const_context(context_)};
        if (!context) {
            return nullptr;
        }
        return reinterpret_cast<kernel_BlockManagerOptions*>(new node::BlockManager::Options{
            .chainparams = *context->m_chainparams,
            .blocks_dir = abs_blocks_dir,
            .notifications = *context->m_notifications});
    } catch (const std::exception& e) {
        LogError("Failed to create block manager options; %s\n", e.what());
        return nullptr;
    }
}

void kernel_block_manager_options_destroy(kernel_BlockManagerOptions* options)
{
    if (options) {
        delete cast_block_manager_options(options);
    }
}

kernel_ChainstateManager* kernel_chainstate_manager_create(
    kernel_ChainstateManagerOptions* chainman_opts_,
    kernel_BlockManagerOptions* blockman_opts_,
    const kernel_Context* context_)
{
    auto chainman_opts{cast_chainstate_manager_options(chainman_opts_)};
    auto blockman_opts{cast_block_manager_options(blockman_opts_)};
    auto context{cast_const_context(context_)};

    try {
        return reinterpret_cast<kernel_ChainstateManager*>(new ChainstateManager{*context->m_interrupt, *chainman_opts, *blockman_opts});
    } catch (const std::exception& e) {
        LogError("Failed to create chainstate manager: %s\n", e.what());
        return nullptr;
    }
}

kernel_ChainstateLoadOptions* kernel_chainstate_load_options_create()
{
    return reinterpret_cast<kernel_ChainstateLoadOptions*>(new node::ChainstateLoadOptions);
}

void kernel_chainstate_load_options_set(
    kernel_ChainstateLoadOptions* chainstate_load_opts_,
    kernel_ChainstateLoadOptionType n_option,
    bool value)
{
    auto chainstate_load_opts{cast_chainstate_load_options(chainstate_load_opts_)};

    switch (n_option) {
    case kernel_ChainstateLoadOptionType::kernel_WIPE_BLOCK_TREE_DB_CHAINSTATE_LOAD_OPTION: {
        chainstate_load_opts->wipe_block_tree_db = value;
        return;
    }
    case kernel_ChainstateLoadOptionType::kernel_WIPE_CHAINSTATE_DB_CHAINSTATE_LOAD_OPTION: {
        chainstate_load_opts->wipe_chainstate_db = value;
        return;
    }
    case kernel_ChainstateLoadOptionType::kernel_BLOCK_TREE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION: {
        chainstate_load_opts->block_tree_db_in_memory = value;
        return;
    }
    case kernel_ChainstateLoadOptionType::kernel_CHAINSTATE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION: {
        chainstate_load_opts->coins_db_in_memory = value;
        return;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

void kernel_chainstate_load_options_destroy(kernel_ChainstateLoadOptions* chainstate_load_opts)
{
    if (chainstate_load_opts) {
        delete cast_chainstate_load_options(chainstate_load_opts);
    }
}

bool kernel_chainstate_manager_load_chainstate(const kernel_Context* context_,
                                               kernel_ChainstateLoadOptions* chainstate_load_opts_,
                                               kernel_ChainstateManager* chainman_)
{
    try {
        auto& chainstate_load_opts{*cast_chainstate_load_options(chainstate_load_opts_)};
        auto& chainman{*cast_chainstate_manager(chainman_)};
        auto& context{*cast_const_context(context_)};

        if (chainstate_load_opts.wipe_block_tree_db && !chainstate_load_opts.wipe_chainstate_db) {
            LogError("Wiping the block tree db without also wiping the chainstate db is currently unsupported.\n");
            return false;
        }

        if (context.m_mempool) {
            chainstate_load_opts.mempool = context.m_mempool.get();
        }

        node::CacheSizes cache_sizes;
        cache_sizes.block_tree_db = 2 << 20;
        cache_sizes.coins_db = 2 << 22;
        cache_sizes.coins = (450 << 20) - (2 << 20) - (2 << 22);
        auto [status, chainstate_err]{node::LoadChainstate(chainman, cache_sizes, chainstate_load_opts)};
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            LogError("Failed to load chain state from your data directory: %s\n", chainstate_err.original);
            return false;
        }
        std::tie(status, chainstate_err) = node::VerifyLoadedChainstate(chainman, chainstate_load_opts);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            LogError("Failed to verify loaded chain state from your datadir: %s\n", chainstate_err.original);
            return false;
        }

        for (Chainstate* chainstate : WITH_LOCK(::cs_main, return chainman.GetAll())) {
            BlockValidationState state;
            if (!chainstate->ActivateBestChain(state, nullptr)) {
                LogError("Failed to connect best block: %s\n", state.ToString());
                return false;
            }
        }
    } catch (const std::exception& e) {
        LogError("Failed to load chainstate: %s\n", e.what());
        return false;
    }
    return true;
}

void kernel_chainstate_manager_destroy(kernel_ChainstateManager* chainman_, const kernel_Context* context_)
{
    if (!chainman_) return;

    auto chainman{cast_chainstate_manager(chainman_)};

    {
        LOCK(cs_main);
        for (Chainstate* chainstate : chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }

    delete chainman;
    return;
}

bool kernel_import_blocks(const kernel_Context* context_,
                          kernel_ChainstateManager* chainman_,
                          const char** block_file_paths,
                          size_t block_file_paths_len)
{
    try {
        auto chainman{cast_chainstate_manager(chainman_)};
        std::vector<fs::path> import_files;
        import_files.reserve(block_file_paths_len);
        for (uint32_t i = 0; i < block_file_paths_len; i++) {
            if (block_file_paths[i] != nullptr) {
                import_files.emplace_back(block_file_paths[i]);
            }
        }
        node::ImportBlocks(*chainman, import_files);
        chainman->ActiveChainstate().ForceFlushStateToDisk();
    } catch (const std::exception& e) {
        LogError("Failed to import blocks: %s\n", e.what());
        return false;
    }
    return true;
}

kernel_Block* kernel_block_create(const unsigned char* raw_block, size_t raw_block_length)
{
    auto block{new CBlock()};

    DataStream stream{Span{raw_block, raw_block_length}};

    try {
        stream >> TX_WITH_WITNESS(*block);
    } catch (const std::exception& e) {
        delete block;
        LogDebug(BCLog::KERNEL, "Block decode failed.\n");
        return nullptr;
    }

    return reinterpret_cast<kernel_Block*>(new std::shared_ptr<CBlock>(block));
}

void kernel_byte_array_destroy(kernel_ByteArray* byte_array)
{
    if (byte_array && byte_array->data) delete[] byte_array->data;
    if (byte_array) delete byte_array;
}

kernel_ByteArray* kernel_copy_block_data(kernel_Block* block_)
{
    auto block{cast_cblocksharedpointer(block_)};

    DataStream ss{};
    ss << TX_WITH_WITNESS(**block);

    auto byte_array{new kernel_ByteArray{
        .data = new unsigned char[ss.size()],
        .size = ss.size(),
    }};

    std::memcpy(byte_array->data, ss.data(), byte_array->size);

    return byte_array;
}

kernel_ByteArray* kernel_copy_block_pointer_data(const kernel_BlockPointer* block_)
{
    auto block{cast_const_cblock(block_)};

    DataStream ss{};
    ss << TX_WITH_WITNESS(*block);

    auto byte_array{new kernel_ByteArray{
        .data = new unsigned char[ss.size()],
        .size = ss.size(),
    }};

    std::memcpy(byte_array->data, ss.data(), byte_array->size);

    return byte_array;
}

void kernel_block_destroy(kernel_Block* block)
{
    if (block) {
        delete cast_cblocksharedpointer(block);
    }
}

kernel_BlockIndex* kernel_get_block_index_from_tip(const kernel_Context* context_, kernel_ChainstateManager* chainman_)
{
    auto chainman{cast_chainstate_manager(chainman_)};
    return reinterpret_cast<kernel_BlockIndex*>(WITH_LOCK(::cs_main, return chainman->ActiveChain().Tip()));
}

kernel_BlockIndex* kernel_get_block_index_from_genesis(const kernel_Context* context_, kernel_ChainstateManager* chainman_)
{
    auto chainman{cast_chainstate_manager(chainman_)};
    return reinterpret_cast<kernel_BlockIndex*>(WITH_LOCK(::cs_main, return chainman->ActiveChain().Genesis()));
}

kernel_BlockIndex* kernel_get_block_index_by_hash(const kernel_Context* context_, kernel_ChainstateManager* chainman_, kernel_BlockHash* block_hash)
{
    auto chainman{cast_chainstate_manager(chainman_)};

    auto hash = uint256{Span<const unsigned char>{(*block_hash).hash, 32}};
    auto block_index = WITH_LOCK(::cs_main, return chainman->m_blockman.LookupBlockIndex(hash));
    if (!block_index) {
        LogDebug(BCLog::KERNEL, "A block with the given hash is not indexed.\n");
        return nullptr;
    }
    return reinterpret_cast<kernel_BlockIndex*>(block_index);
}

kernel_BlockIndex* kernel_get_block_index_by_height(const kernel_Context* context_, kernel_ChainstateManager* chainman_, int height)
{
    auto chainman{cast_chainstate_manager(chainman_)};

    LOCK(cs_main);

    if (height < 0 || height > chainman->ActiveChain().Height()) {
        LogDebug(BCLog::KERNEL, "Block height is out of range.\n");
        return nullptr;
    }
    return reinterpret_cast<kernel_BlockIndex*>(chainman->ActiveChain()[height]);
}

kernel_BlockIndex* kernel_get_next_block_index(const kernel_Context* context_, kernel_BlockIndex* block_index_, kernel_ChainstateManager* chainman_)
{
    auto block_index{cast_block_index(block_index_)};
    auto chainman{cast_chainstate_manager(chainman_)};

    auto next_block_index{WITH_LOCK(::cs_main, return chainman->ActiveChain().Next(block_index))};

    if (!next_block_index) {
        LogTrace(BCLog::KERNEL, "The block index is the tip of the current chain, it does not have a next.\n");
    }

    return reinterpret_cast<kernel_BlockIndex*>(next_block_index);
}

kernel_BlockIndex* kernel_get_previous_block_index(kernel_BlockIndex* block_index_)
{
    CBlockIndex* block_index{cast_block_index(block_index_)};

    if (!block_index->pprev) {
        LogTrace(BCLog::KERNEL, "The block index is the genesis, it has no previous.\n");
        return nullptr;
    }

    return reinterpret_cast<kernel_BlockIndex*>(block_index->pprev);
}

kernel_Block* kernel_read_block_from_disk(const kernel_Context* context_,
                                          kernel_ChainstateManager* chainman_,
                                          kernel_BlockIndex* block_index_)
{
    auto chainman{cast_chainstate_manager(chainman_)};
    CBlockIndex* block_index{cast_block_index(block_index_)};

    auto block{new std::shared_ptr<CBlock>(new CBlock{})};
    if (!chainman->m_blockman.ReadBlockFromDisk(**block, *block_index)) {
        LogError("Failed to read block from disk.\n");
        return nullptr;
    }
    return reinterpret_cast<kernel_Block*>(block);
}

kernel_BlockUndo* kernel_read_block_undo_from_disk(const kernel_Context* context_,
                                                   kernel_ChainstateManager* chainman_,
                                                   kernel_BlockIndex* block_index_)
{
    auto chainman{cast_chainstate_manager(chainman_)};
    auto block_index{cast_block_index(block_index_)};

    if (block_index->nHeight < 1) {
        LogError("The genesis block does not have undo data.\n");
        return nullptr;
    }
    auto block_undo{new CBlockUndo{}};
    if (!chainman->m_blockman.UndoReadFromDisk(*block_undo, *block_index)) {
        LogError("Failed to read undo data from disk.\n");
        return nullptr;
    }
    return reinterpret_cast<kernel_BlockUndo*>(block_undo);
}

void kernel_block_index_destroy(kernel_BlockIndex* block_index)
{
    // This is just a dummy function. The user does not control block index memory.
    return;
}

uint64_t kernel_block_undo_size(kernel_BlockUndo* block_undo_)
{
    auto block_undo{cast_block_undo(block_undo_)};
    return block_undo->vtxundo.size();
}

void kernel_block_undo_destroy(kernel_BlockUndo* block_undo)
{
    if (block_undo) {
        delete cast_block_undo(block_undo);
    }
}

uint64_t kernel_get_transaction_undo_size(kernel_BlockUndo* block_undo_, uint64_t transaction_undo_index)
{
    auto block_undo{cast_block_undo(block_undo_)};
    return block_undo->vtxundo[transaction_undo_index].vprevout.size();
}

kernel_TransactionOutput* kernel_get_undo_output_by_index(kernel_BlockUndo* block_undo_,
                                                          uint64_t transaction_undo_index,
                                                          uint64_t output_index)
{
    auto block_undo{cast_block_undo(block_undo_)};

    if (transaction_undo_index >= block_undo->vtxundo.size()) {
        LogInfo("transaction undo index is out of bounds.\n");
        return nullptr;
    }

    const auto& tx_undo = block_undo->vtxundo[transaction_undo_index];

    if (output_index >= tx_undo.vprevout.size()) {
        LogInfo("previous output index is out of bounds.\n");
        return nullptr;
    }

    const auto& prevout{tx_undo.vprevout.at(output_index).out};
    std::unique_ptr<unsigned char[]> byte_array(new unsigned char[prevout.scriptPubKey.size()]);
    std::copy(prevout.scriptPubKey.begin(), prevout.scriptPubKey.end(), byte_array.get());

    auto kernel_prevout{new kernel_TransactionOutput{}};

    kernel_prevout->value = prevout.nValue;
    kernel_prevout->script_pubkey_len = prevout.scriptPubKey.size();
    kernel_prevout->script_pubkey = byte_array.release();

    return reinterpret_cast<kernel_TransactionOutput*>(kernel_prevout);
}

kernel_BlockIndexInfo* kernel_get_block_index_info(kernel_BlockIndex* block_index_)
{
    auto block_index{cast_block_index(block_index_)};
    return new kernel_BlockIndexInfo{block_index->nHeight};
}

void kernel_block_index_info_destroy(kernel_BlockIndexInfo* info)
{
    if (info) delete info;
}

void kernel_transaction_output_destroy(kernel_TransactionOutput* transaction_output)
{
    if (transaction_output && transaction_output->script_pubkey) {
        delete[] transaction_output->script_pubkey;
    }
    if (transaction_output) delete transaction_output;
}

bool kernel_chainstate_manager_process_block_header(const kernel_Context* context_, kernel_ChainstateManager* chainman_, kernel_BlockHeader* header_)
{
    auto& chainman{*cast_chainstate_manager(chainman_)};
    auto header{cast_block_header(header_)};

    std::vector<CBlockHeader> headers{*header};
    BlockValidationState state;
    return chainman.ProcessNewBlockHeaders(headers, true, state);
}

bool kernel_chainstate_manager_process_block(
    const kernel_Context* context_,
    kernel_ChainstateManager* chainman_,
    kernel_Block* block_, 
    kernel_ProcessBlockStatus* status)
{
    auto& chainman{*cast_chainstate_manager(chainman_)};

    auto blockptr{cast_cblocksharedpointer(block_)};

    CBlock& block{**blockptr};

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        if (status) *status = kernel_PROCESS_BLOCK_ERROR_NO_COINBASE;
        LogError("Block cannot be processed without a coinbase transaction.\n");
        return false;
    }

    uint256 hash{block.GetHash()};
    {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman.m_blockman.LookupBlockIndex(hash)};
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                if (status) *status = kernel_PROCESS_BLOCK_DUPLICATE;
                LogError("Block was already validated.\n");
                return false;
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                if (status) *status = kernel_PROCESS_BLOCK_INVALID_DUPLICATE;
                LogError("Block was already validated and is invalid.\n");
                return false;
            }
        }
    }

    {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock)};
        if (pindex) {
            chainman.UpdateUncommittedBlockStructures(block, pindex);
        }
    }

    bool new_block;
    bool accepted{chainman.ProcessNewBlock(*blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block)};

    if (!new_block && accepted) {
        if (status) *status = kernel_PROCESS_BLOCK_DUPLICATE;
        return false;
    }
    if (!accepted) {
        if (status) *status = kernel_PROCESS_BLOCK_INVALID;
    }
    return accepted;
}

kernel_CoinsViewCursor* kernel_chainstate_coins_cursor_create(kernel_ChainstateManager* chainman_)
{
    auto chainman{cast_chainstate_manager(chainman_)};

    std::unique_ptr<CCoinsViewCursor> cursor{};
    {
        chainman->ActiveChainstate().ForceFlushStateToDisk();
        cursor = WITH_LOCK(::cs_main, return chainman->ActiveChainstate().CoinsDB()).Cursor();
        if (!cursor->Valid()) {
            LogError("Cursor is not valid, probably the chainstate is not initialized correctly.\n");
            return nullptr;
        }
    }
    return reinterpret_cast<kernel_CoinsViewCursor*>(cursor.release());
}

bool kernel_coins_cursor_next(kernel_CoinsViewCursor* cursor_)
{
    auto cursor{cast_coins_view_cursor(cursor_)};
    cursor->Next();
    return cursor->Valid();
}

kernel_OutPoint* kernel_coins_cursor_get_key(kernel_CoinsViewCursor* cursor_)
{
    auto cursor{cast_coins_view_cursor(cursor_)};
    COutPoint key;
    {
        LOCK(cs_main);
        if (!cursor->Valid()) {
            LogDebug(BCLog::KERNEL, "Cursor is not valid, probably iterated out of bounds.\n");
            return nullptr;
        }
        cursor->GetKey(key);
    }

    kernel_OutPoint* out_point{ new kernel_OutPoint{
        .hash = {},
        .n = key.n,
    }};
    std::memcpy(out_point->hash, key.hash.data(), sizeof(out_point->hash));
    return out_point;
}

kernel_Coin* kernel_coins_cursor_get_value(kernel_CoinsViewCursor* cursor_)
{
    auto cursor{cast_coins_view_cursor(cursor_)};

    Coin coin;
    {
        LOCK(cs_main);
        if (!cursor->Valid()) {
            LogDebug(BCLog::KERNEL, "Cursor is not valid, probably iterated out of bounds.\n");
            return nullptr;
        }
        if (!cursor->GetValue(coin)) return nullptr;
    }

    std::unique_ptr<unsigned char[]> byte_array(new unsigned char[coin.out.scriptPubKey.size()]);
    std::copy(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end(), byte_array.get());

    auto kernel_coin{new kernel_Coin{
        .out =  kernel_TransactionOutput {
            .value = coin.out.nValue,
            .script_pubkey = byte_array.release(),
            .script_pubkey_len = coin.out.scriptPubKey.size(),
        },
        .is_coinbase = coin.fCoinBase,
        .confirmation_height = coin.nHeight,
    }};

    return kernel_coin;
}

void kernel_coins_cursor_destroy(kernel_CoinsViewCursor* cursor)
{
    if (!cursor) {
        return;
    }
    delete cast_coins_view_cursor(cursor);
}

kernel_Coin* kernel_get_coin_by_out_point(kernel_ChainstateManager* chainman_, const kernel_OutPoint* out_point)
{
    auto chainman{cast_chainstate_manager(chainman_)};
    Coin coin;
    COutPoint key{Txid::FromUint256(uint256{out_point->hash}), out_point->n };
    {
        LOCK(cs_main);
        if (!chainman->ActiveChainstate().CoinsDB().HaveCoin(key)) {
            LogDebug(BCLog::KERNEL, "Out point has no entry in coins db");
            return nullptr;
        }
        chainman->ActiveChainstate().CoinsDB().GetCoin(key, coin);
    }

    std::unique_ptr<unsigned char[]> byte_array(new unsigned char[coin.out.scriptPubKey.size()]);
    std::copy(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end(), byte_array.get());

    auto kernel_coin{new kernel_Coin{
        .out =  kernel_TransactionOutput {
            .value = coin.out.nValue,
            .script_pubkey = byte_array.release(),
            .script_pubkey_len = coin.out.scriptPubKey.size(),
        },
        .is_coinbase = coin.fCoinBase,
        .confirmation_height = coin.nHeight,
    }};

    return kernel_coin;
}

void kernel_out_point_destroy(kernel_OutPoint* out_point)
{
    if (out_point) delete out_point;
}

void kernel_coin_destroy(kernel_Coin* coin)
{
    if (coin && coin->out.script_pubkey) delete[] coin->out.script_pubkey;
    if (coin) delete coin;
}

kernel_BlockHeader* kernel_get_block_header(kernel_Block* block_)
{
    auto block{cast_cblocksharedpointer(block_)};
    return reinterpret_cast<kernel_BlockHeader*>(new CBlockHeader{(*block)->GetBlockHeader()});
} 

kernel_BlockHeader* kernel_block_header_create(const unsigned char* raw_block_header, size_t raw_block_header_len)
{
    auto header{new CBlockHeader{}};

    DataStream stream{Span{raw_block_header, raw_block_header_len}};

    try {
        stream >> *header;
    } catch (const std::exception& e) {
        delete header;
        LogError("Block header decode failed.\n");
        return nullptr;
    }

    return reinterpret_cast<kernel_BlockHeader*>(header);
}

void kernel_block_header_destroy(kernel_BlockHeader* header)
{
    if (header) {
        delete cast_block_header(header);
    }
}

kernel_ByteArray* kernel_copy_block_header_data(kernel_BlockHeader* header_)
{
    auto header{cast_block_header(header_)};

    DataStream ss{};
    ss << *header;

    auto byte_array{new kernel_ByteArray{
        .data = new unsigned char[ss.size()],
        .size = ss.size(),
    }};

    std::memcpy(byte_array->data, ss.data(), byte_array->size);

    return byte_array;
}

bool kernel_is_block_mutated(kernel_Block* block_, bool check_witness_root)
{
    auto block{cast_cblocksharedpointer(block_)};
    return IsBlockMutated(**block, check_witness_root);
}

size_t kernel_number_of_transactions_in_block(kernel_Block* block_)
{
    auto block{cast_cblocksharedpointer(block_)};
    return (**block).vtx.size();
}

kernel_Transaction* kernel_get_transaction_by_index(kernel_Block* block_, uint64_t index)
{
    auto block{cast_cblocksharedpointer(block_)};
    if (index >= (**block).vtx.size()) {
        LogDebug(BCLog::KERNEL, "Index is not in range of available transactions in this block.\n");
        return nullptr;
    }
    return reinterpret_cast<kernel_Transaction*>(new CTransactionRef{(**block).vtx[index]});
}

kernel_ByteArray* kernel_copy_transaction_data(kernel_Transaction* transaction_)
{
    auto transaction{cast_transaction_ref(transaction_)};

    DataStream ss{};
    ss << TX_WITH_WITNESS(**transaction);

    auto byte_array{new kernel_ByteArray{
        .data = new unsigned char[ss.size()],
        .size = ss.size(),
    }};

    std::memcpy(byte_array->data, ss.data(), byte_array->size);

    return byte_array;
}

kernel_Transaction* kernel_transaction_create(const unsigned char* raw_transaction, size_t raw_transaction_len)
{
    DataStream stream{Span{raw_transaction, raw_transaction_len}};

    CTransaction* transaction;
    try {
        transaction = new CTransaction{deserialize, TX_WITH_WITNESS, stream};
    } catch (const std::exception& e) {
        LogDebug(BCLog::KERNEL, "Transaction decode failed.\n");
        return nullptr;
    }
    return reinterpret_cast<kernel_Transaction*>(new std::shared_ptr<CTransaction>{transaction});
}

void kernel_transaction_destroy(kernel_Transaction* transaction)
{
    if (transaction) {
        delete cast_transaction_ref(transaction);
    }
}
