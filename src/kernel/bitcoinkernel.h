// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_H
#define BITCOIN_KERNEL_BITCOINKERNEL_H

#ifndef __cplusplus
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif // __cplusplus


#if !defined(BITCOINKERNEL_GNUC_PREREQ)
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define BITCOINKERNEL_GNUC_PREREQ(_maj, _min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((_maj) << 16) + (_min))
#else
#define BITCOINKERNEL_GNUC_PREREQ(_maj, _min) 0
#endif
#endif

/* Warning attributes */
#if defined(__GNUC__) && BITCOINKERNEL_GNUC_PREREQ(3, 4)
#define BITCOINKERNEL_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#define BITCOINKERNEL_WARN_UNUSED_RESULT
#endif
#if !defined(BITCOINKERNEL_BUILD) && defined(__GNUC__) && BITCOINKERNEL_GNUC_PREREQ(3, 4)
#define BITCOINKERNEL_ARG_NONNULL(_x) __attribute__((__nonnull__(_x)))
#else
#define BITCOINKERNEL_ARG_NONNULL(_x)
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * ------ Context ------
 *
 * The library provides a built-in static constant kernel context. This context
 * offers only limited functionality. It detects and self-checks the correct
 * sha256 implementation, initializes the random number generator and
 * self-checks the secp256k1 static context. It is used internally for otherwise
 * "context-free" operations.
 *
 * The user can create their own context for passing it to state-rich validation
 * functions and holding callbacks for kernel events.
 *
 * ------ Error handling ------
 *
 * Functions communicate an error through their return types, usually returning
 * a nullptr, or false if an error is encountered. Additionally, verification
 * functions, e.g. for scripts, may communicate more detailed error information
 * through status code out parameters.
 * 
 * ------ Pointer and argument conventions ------
 *
 * The user is responsible for de-allocating the memory owned by pointers
 * returned by functions. Typically pointers returned by *_create(...) functions
 * can be de-allocated by corresponding *_destroy(...) functions.
 *
 * Pointer arguments make no assumptions on their lifetime. Once the function
 * returns the user can safely de-allocate the passed in arguments.
 *
 * Pointers passed by callbacks are not owned by the user and are only valid for
 * the duration of it. They should not be de-allocated by the user.
 *
 * Array lengths follow the pointer argument they describe.
 */

/**
 * Opaque data structure for holding a logging connection.
 *
 * The logging connection can be used to manually stop logging.
 *
 * Messages that were logged before a connection is created are buffered in a
 * 1MB buffer. Logging can alternatively be permanently disabled by calling
 * kernel_disable_logging().
 */
typedef struct kernel_LoggingConnection kernel_LoggingConnection;

/**
 * Opaque data structure for holding options for creating a new kernel context.
 *
 * Once a kernel context has been created from these options, they may be
 * destroyed. The options hold the notification callbacks as well as the
 * selected chain type until they are passed to the context. Their content and
 * scope can be expanded over time.
 */
typedef struct kernel_ContextOptions kernel_ContextOptions;

/**
 * Opaque data structure for holding a kernel context.
 *
 * The kernel context is used to initialize internal state and hold the chain
 * parameters and callbacks for handling error and validation events. Once other
 * validation objects are instantiated from it, the context needs to be kept in
 * memory for the duration of their lifetimes.
 *
 * A constructed context can be safely used from multiple threads, but functions
 * taking it as a non-cost argument need exclusive access to it.
 */
typedef struct kernel_Context kernel_Context;

/** Callback function types */

/**
 * Function signature for the global logging callback. All bitcoin kernel
 * internal logs will pass through this callback.
 */
typedef void (*kernel_LogCallback)(void* user_data, const char* message);

/**
 * A collection of logging categories that may be encountered by kernel code.
 */
typedef enum {
    kernel_LOG_ALL = 0,
    kernel_LOG_BENCH,
    kernel_LOG_BLOCKSTORAGE,
    kernel_LOG_COINDB,
    kernel_LOG_LEVELDB,
    kernel_LOG_LOCK,
    kernel_LOG_MEMPOOL,
    kernel_LOG_PRUNE,
    kernel_LOG_RAND,
    kernel_LOG_REINDEX,
    kernel_LOG_VALIDATION,
    kernel_LOG_KERNEL,
} kernel_LogCategory;

/**
 * The level at which logs should be produced.
 */
typedef enum {
    kernel_LOG_INFO = 0,
    kernel_LOG_DEBUG,
    kernel_LOG_TRACE,
} kernel_LogLevel;

/**
 * Options controlling the format of log messages.
 */
typedef struct {
    bool log_timestamps;               //!< Prepend a timestamp to log messages.
    bool log_time_micros;              //!< Log timestamps in microsecond precision.
    bool log_threadnames;              //!< Prepend the name of the thread to log messages.
    bool log_sourcelocations;          //!< Prepend the source location to log messages.
    bool always_print_category_levels; //!< Prepend the log category and level to log messages.
} kernel_LoggingOptions;

/**
 * A collection of status codes that may be issued by the script verify function.
 */
typedef enum {
    kernel_SCRIPT_VERIFY_OK = 0,
    kernel_SCRIPT_VERIFY_ERROR_TX_INPUT_INDEX, //!< The provided input index is out of range of the actual number of inputs of the transaction.
    kernel_SCRIPT_VERIFY_ERROR_TX_SIZE_MISMATCH, //!< The provided tx_to_len argument does not match the actual size of the transaction.
    kernel_SCRIPT_VERIFY_ERROR_TX_DESERIALIZE, //!< The provided tx could not be de-serialized.
    kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS, //!< The provided bitfield for the flags was invalid.
    kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION, //!< The flags very combined in an invalid way.
    kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED, //!< The taproot flag was set, so valid spent_outputs have to be provided.
    kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_MISMATCH, //!< The number of spent outputs does not match the number of inputs of the tx.
} kernel_ScriptVerifyStatus;

/**
 * Script verification flags that may be composed with each other.
 */
typedef enum
{
    kernel_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    kernel_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), //!< evaluate P2SH (BIP16) subscripts
    kernel_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), //!< enforce strict DER (BIP66) compliance
    kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY           = (1U << 4), //!< enforce NULLDUMMY (BIP147)
    kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), //!< enable CHECKLOCKTIMEVERIFY (BIP65)
    kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10), //!< enable CHECKSEQUENCEVERIFY (BIP112)
    kernel_SCRIPT_FLAGS_VERIFY_WITNESS             = (1U << 11), //!< enable WITNESS (BIP141)

    kernel_SCRIPT_FLAGS_VERIFY_TAPROOT             = (1U << 17), //!< enable TAPROOT (BIPs 341 & 342)
    kernel_SCRIPT_FLAGS_VERIFY_ALL                 = kernel_SCRIPT_FLAGS_VERIFY_P2SH |
                                                     kernel_SCRIPT_FLAGS_VERIFY_DERSIG |
                                                     kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY |
                                                     kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                                     kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY |
                                                     kernel_SCRIPT_FLAGS_VERIFY_WITNESS |
                                                     kernel_SCRIPT_FLAGS_VERIFY_TAPROOT
} kernel_ScriptFlags;

/**
 * A helper struct for a single transaction output.
 */
typedef struct {
    int64_t value;
    const unsigned char* script_pubkey;
    size_t script_pubkey_len;
} kernel_TransactionOutput;

/**
 * @brief Verify if the input at input_index of tx_to spends the script pubkey
 * under the constraints specified by flags. If the witness flag is set the
 * amount parameter is used. If the taproot flag is set, the spent outputs
 * parameter is used to validate taproot transactions.
 *
 * @param[in] script_pubkey     Non-null, serialized script pubkey to be spent.
 * @param[in] script_pubkey_len Length of the script pubkey to be spent.
 * @param[in] amount            Amount of the script pubkey's associated output. May be zero if
 *                              the witness flag is not set.
 * @param[in] tx_to             Non-null, serialized transaction spending the script_pubkey.
 * @param[in] tx_to_len         Length of the serialized transaction spending the script_pubkey.
 * @param[in] spent_outputs     Nullable if the taproot flag is not set. Points to an array of
 *                              outputs spent by the transaction.
 * @param[in] spent_outputs_len Length of the spent_outputs array.
 * @param[in] input_index       Index of the input in tx_to spending the script_pubkey.
 * @param[in] flags             Bitfield of kernel_ScriptFlags controlling validation constraints.
 * @param[out] status           Nullable, will be set to an error code if the operation fails.
 *                              Should be set to kernel_SCRIPT_VERIFY_OK.
 * @return                      True if the script is valid.
 */
bool BITCOINKERNEL_WARN_UNUSED_RESULT kernel_verify_script(
    const unsigned char* script_pubkey, size_t script_pubkey_len,
    int64_t amount,
    const unsigned char* tx_to, size_t tx_to_len,
    const kernel_TransactionOutput* spent_outputs, size_t spent_outputs_len,
    unsigned int input_index,
    unsigned int flags,
    kernel_ScriptVerifyStatus* status
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(4);

/**
 * @brief This disables the global internal logger. No log messages will be
 * buffered internally anymore once this is called and the buffer is cleared.
 * This function should only be called once. Log messages will be buffered until
 * this function is called, or a logging connection is created.
 */
void kernel_disable_logging();

/**
 * @brief Set the log level of the global internal logger. This does not enable
 * the selected categories. Use `kernel_enable_log_category` to start logging
 * from a specific, or all categories.
 *
 * @param[in] category If kernel_LOG_ALL is chosen, all messages at the specified level
 *                     will be logged. Otherwise only messages from the specified category
 *                     will be logged at the specified level and above.
 * @param[in] level    Log level at which the log category is set.
 * @return             True on success.
 */
bool BITCOINKERNEL_WARN_UNUSED_RESULT kernel_add_log_level_category(const kernel_LogCategory category, kernel_LogLevel level);

/**
 * @brief Enable a specific log category for the global internal logger.
 *
 * @param[in] category If kernel_LOG_ALL is chosen, all categories will be enabled.
 * @return             True on success.
 */
bool BITCOINKERNEL_WARN_UNUSED_RESULT kernel_enable_log_category(const kernel_LogCategory category);

/**
 * Disable a specific log category for the global internal logger.
 *
 * @param[in] category If kernel_LOG_ALL is chosen, all categories will be disabled.
 * @return             True on success.
 */
bool BITCOINKERNEL_WARN_UNUSED_RESULT kernel_disable_log_category(const kernel_LogCategory category);

/**
 * @brief Start logging messages through the provided callback. Log messages
 * produced before this function is first called are buffered and on calling this
 * function are logged immediately.
 *
 * @param[in] callback  Non-null, function through which messages will be logged.
 * @param[in] user_data Nullable, holds a user-defined opaque structure. Is passed back
 *                      to the user through the callback.
 * @param[in] options   Sets formatting options of the log messages.
 * @return              A new kernel logging connection, or null on error.
 */
kernel_LoggingConnection* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_logging_connection_create(
    kernel_LogCallback callback,
    void* user_data,
    const kernel_LoggingOptions options
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * Stop logging and destroy the logging connection.
 */
void kernel_logging_connection_destroy(kernel_LoggingConnection* logging_connection);

/**
 * Creates an empty context options.
 */
kernel_ContextOptions* kernel_context_options_create();

/**
 * Destroy the context options.
 */
void kernel_context_options_destroy(kernel_ContextOptions* context_options);

/**
 * @brief Create a new kernel context. If the options have not been previously
 * set, their corresponding fields will be initialized to default values; the
 * context will assume mainnet chain parameters and won't attempt to call the
 * kernel notification callbacks.
 *
 * @param[in] context_options Nullable, created with kernel_context_options_create.
 * @return                    The allocated kernel context, or null on error.
 */
kernel_Context* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_context_create(
    const kernel_ContextOptions* context_options);

/**
 * Destroy the context.
 */
void kernel_context_destroy(kernel_Context* context);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // BITCOIN_KERNEL_BITCOINKERNEL_H
