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
 * The kernel notifications issue callbacks for errors. These are usually
 * indicative of a system error. If such an error is issued, it is recommended
 * to halt and tear down the existing kernel objects. Remediating the error may
 * require system intervention by the user.
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
 * Opaque data structure for holding the chain parameters.
 *
 * These are eventually placed into a kernel context through the kernel context
 * options. The parameters describe the properties of a chain, and may be
 * instantiated for either mainnet, testnet, signet, or regtest.
 */
typedef struct kernel_ChainParameters kernel_ChainParameters;

/**
 * Opaque data structure for holding callbacks for reacting to events that may
 * be encountered during library operations.
 */
typedef struct kernel_Notifications kernel_Notifications;

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

/**
 * Opaque data structure for holding a block index pointer.
 *
 * This is a pointer to an element in the block index currently in memory of the
 * chainstate manager. It is valid for the lifetime of the chainstate manager it
 * was retrieved from.
 */
typedef struct kernel_BlockIndex kernel_BlockIndex;

/**
 * Opaque data structure for holding options for creating a new chainstate
 * manager.
 *
 * The chainstate manager options are used to set some parameters for the
 * chainstate manager. For now it just holds default options.
 */
typedef struct kernel_ChainstateManagerOptions kernel_ChainstateManagerOptions;

/**
 * Opaque data structure for holding options for creating a new chainstate
 * manager.
 *
 * The chainstate manager has an internal block manager that takes its own set
 * of parameters. It is initialized with default options.
 */
typedef struct kernel_BlockManagerOptions kernel_BlockManagerOptions;

/**
 * Opaque data structure for holding a chainstate manager.
 *
 * The chainstate manager is the central object for doing validation tasks as
 * well as retrieving data from the chain. Internally it is a complex data
 * structure with diverse functionality.
 *
 * The chainstate manager is only valid for as long as the context with which it
 * was created remains in memory.
 *
 * Its functionality will be more and more exposed in the future.
 */
typedef struct kernel_ChainstateManager kernel_ChainstateManager;

/**
 * Opaque data structure for holding parameters used for loading the chainstate
 * of a chainstate manager.
 *
 * Is initialized with default parameters.
 */
typedef struct kernel_ChainstateLoadOptions kernel_ChainstateLoadOptions;

/**
 * Opaque data structure for holding a block.
 */
typedef struct kernel_Block kernel_Block;

/** Current sync state passed to tip changed callbacks. */
typedef enum {
    kernel_INIT_REINDEX,
    kernel_INIT_DOWNLOAD,
    kernel_POST_INIT
} kernel_SynchronizationState;

/** Possible warning types issued by validation. */
typedef enum {
    kernel_UNKNOWN_NEW_RULES_ACTIVATED,
    kernel_LARGE_WORK_INVALID_CHAIN
} kernel_Warning;

/** Callback function types */

/**
 * Function signature for the global logging callback. All bitcoin kernel
 * internal logs will pass through this callback.
 */
typedef void (*kernel_LogCallback)(void* user_data, const char* message);

/**
 * Function signatures for the kernel notifications.
 */
typedef void (*kernel_NotifyBlockTip)(void* user_data, kernel_SynchronizationState state, kernel_BlockIndex* index);
typedef void (*kernel_NotifyHeaderTip)(void* user_data, kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync);
typedef void (*kernel_NotifyProgress)(void* user_data, const char* title, int progress_percent, bool resume_possible);
typedef void (*kernel_NotifyWarningSet)(void* user_data, kernel_Warning warning, const char* message);
typedef void (*kernel_NotifyWarningUnset)(void* user_data, kernel_Warning warning);
typedef void (*kernel_NotifyFlushError)(void* user_data, const char* message);
typedef void (*kernel_NotifyFatalError)(void* user_data, const char* message);

/**
 * Available types of context options. Passed with a corresponding value to
 * kernel_context_options_set(..).
 */
typedef enum {
    kernel_CHAIN_PARAMETERS_OPTION = 0, //!< Set the chain parameters, value must be a valid pointer
                                        //!< to a kernel_ChainParameters struct.
    kernel_NOTIFICATIONS_OPTION,        //!< Set the kernel notifications, value must be a valid
                                        //!< pointer to a kernel_Notifications struct.
} kernel_ContextOptionType;

/**
 * Available types of chainstate load options. Passed with a corresponding value
 * to kernel_chainstate_load_options_set(..).
 */
typedef enum {
    kernel_WIPE_BLOCK_TREE_DB_CHAINSTATE_LOAD_OPTION = 0,  //! Set the wipe block tree db option, default is false.
                                                           //! Should only be set in combination with wiping the chainstate db.
                                                           //! Will trigger a reindex once kernel_import_blocks is called.
    kernel_WIPE_CHAINSTATE_DB_CHAINSTATE_LOAD_OPTION,      //! Set the wipe chainstate option, default is false.
    kernel_BLOCK_TREE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION, //! Set the block tree db in memory option, default is false.
    kernel_CHAINSTATE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION, //! Set the coins db in memory option, default is false.
} kernel_ChainstateLoadOptionType;

/**
 * A struct for holding the kernel notification callbacks. The user data pointer
 * may be used to point to user-defined structures to make processing the
 * notifications easier.
 */
typedef struct {
    void* user_data;                         //!< Holds a user-defined opaque structure that is passed to the notification callbacks.
    kernel_NotifyBlockTip block_tip;         //!< The chain's tip was updated to the provided block index.
    kernel_NotifyHeaderTip header_tip;       //!< A new best block header was added.
    kernel_NotifyProgress progress;          //!< Reports on current block synchronization progress.
    kernel_NotifyWarningSet warning_set;     //!< A warning issued by the kernel library during validation.
    kernel_NotifyWarningUnset warning_unset; //!< A previous condition leading to the issuance of a warning is no longer given.
    kernel_NotifyFlushError flush_error;     //!< An error encountered when flushing data to disk.
    kernel_NotifyFatalError fatal_error;     //!< A un-recoverable system error encountered by the library.
} kernel_NotificationInterfaceCallbacks;

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
 * Process block statuses.
 */
typedef enum {
    kernel_PROCESS_BLOCK_OK = 0,
    kernel_PROCESS_BLOCK_INVALID,           //!< The block failed processing.
    kernel_PROCESS_BLOCK_ERROR_NO_COINBASE, //!< To process a block, a coinbase transaction has to be part of it.
    kernel_PROCESS_BLOCK_DUPLICATE,         //!< The block has been processed before.
    kernel_PROCESS_BLOCK_INVALID_DUPLICATE, //!< The block has been process before, and it was invalid.
} kernel_ProcessBlockStatus;

/**
 * A helper struct for a single transaction output.
 */
typedef struct {
    int64_t value;
    const unsigned char* script_pubkey;
    size_t script_pubkey_len;
} kernel_TransactionOutput;

/**
 * Chain type used for creating chain params.
 */
typedef enum {
    kernel_CHAIN_TYPE_MAINNET = 0,
    kernel_CHAIN_TYPE_TESTNET,
    kernel_CHAIN_TYPE_SIGNET,
    kernel_CHAIN_TYPE_REGTEST,
} kernel_ChainType;

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
 * @brief Creates a chain parameters struct with default parameters based on the
 * passed in chain type.
 *
 * @param[in] chain_type Controls the chain parameters type created.
 * @return               An allocated chain parameters opaque struct.
 */
const kernel_ChainParameters* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_chain_parameters_create(
    const kernel_ChainType chain_type);

/**
 * Destroy the chain parameters.
 */
void kernel_chain_parameters_destroy(const kernel_ChainParameters* chain_parameters);

/**
 * @brief Creates an object for holding the kernel notification callbacks.
 *
 * @param[in] callbacks Holds the callbacks that will be invoked by the kernel notifications.
 */
kernel_Notifications* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_notifications_create(
    kernel_NotificationInterfaceCallbacks callbacks);

/**
 * Destroy the kernel notifications.
 */
void kernel_notifications_destroy(const kernel_Notifications* notifications);

/**
 * Creates an empty context options.
 */
kernel_ContextOptions* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_context_options_create();

/**
 * @brief Sets a single, specific field in the options. The option type has to
 * match the option value.
 *
 * @param[in] context_options Non-null, previously created with kernel_context_options_create.
 * @param[in] n_option        Describes the option field that should be set with the value.
 * @param[in] value           Non-null, single value that will be used to set the field selected by n_option.
 * @return                    True on success, false if an error occurred, like the selected option not
 *                            corresponding to the passed in value.
 */
bool BITCOINKERNEL_WARN_UNUSED_RESULT kernel_context_options_set(
    kernel_ContextOptions* context_options,
    const kernel_ContextOptionType n_option,
    const void* value
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(3);

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
 * @brief Interrupt can be used to halt long-running validation functions like
 * when reindexing, importing or processing blocks.
 *
 * @param[in] context  Non-null.
 * @return             True if the interrupt was successful.
 */
bool BITCOINKERNEL_WARN_UNUSED_RESULT kernel_context_interrupt(
    kernel_Context* context
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * Destroy the context.
 */
void kernel_context_destroy(kernel_Context* context);

/**
 * @brief Create options for the chainstate manager.
 *
 * @param[in] context        Non-null, the created options will associate with this kernel context
 *                           for the duration of their lifetime. The same context needs to be used
 *                           when instantiating the chainstate manager.
 * @param[in] data_directory Non-null, directory containing the chainstate data. If the directory
 *                           does not exist yet, it will be created.
 * @return                   The allocated chainstate manager options, or null on error.
 */
kernel_ChainstateManagerOptions* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_chainstate_manager_options_create(
    const kernel_Context* context,
    const char* data_directory
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(2);

/**
 * Destroy the chainstate manager options.
 */
void kernel_chainstate_manager_options_destroy(kernel_ChainstateManagerOptions* chainstate_manager_options);

/**
 * @brief Create options for the block manager. The block manager is used
 * internally by the chainstate manager for block storage and indexing.
 *
 * @param[in] context          Non-null, the created options will associate with this kernel context
 *                             for the duration of their lifetime. The same context needs to be used
 *                             when instantiating the chainstate manager.
 * @param[in] blocks_directory Non-null, directory containing the block data. If the directory does
 *                             not exist yet, it will be created.
 * @return                     The allocated block manager options, or null on error.
 */
kernel_BlockManagerOptions* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_block_manager_options_create(
    const kernel_Context* context,
    const char* blocks_directory
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(2);

/**
 * Destroy the block manager options.
 */
void kernel_block_manager_options_destroy(kernel_BlockManagerOptions* block_manager_options);

/**
 * @brief Create a chainstate manager. This is the main object for many
 * validation tasks as well as for retrieving data from the chain. It is only
 * valid for as long as the passed in context also remains in memory.
 *
 * @param[in] chainstate_manager_options Non-null, created by kernel_chainstate_manager_options_create.
 * @param[in] block_manager_options      Non-null, created by kernel_block_manager_options_create.
 * @param[in] context                    Non-null, the created chainstate manager will associate with this
 *                                       kernel context for the duration of its lifetime. The same context
 *                                       needs to be used for later interactions with the chainstate manager.
 * @return                               The allocated chainstate manager, or null on error.
 */
kernel_ChainstateManager* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_chainstate_manager_create(
    kernel_ChainstateManagerOptions* chainstate_manager_options,
    kernel_BlockManagerOptions* block_manager_options,
    const kernel_Context* context
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(2) BITCOINKERNEL_ARG_NONNULL(3);

/**
 * Destroy the chainstate manager.
 */
void kernel_chainstate_manager_destroy(kernel_ChainstateManager* chainstate_manager, const kernel_Context* context);

/**
 * Create options for loading the chainstate.
 */
kernel_ChainstateLoadOptions* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_chainstate_load_options_create();

/**
 * @brief Sets a single, specific field in the chainstate load options. The
 * option type has to match the option value.
 *
 * @param[in] chainstate_load_options Non-null, created with kernel_chainstate_load_options_create.
 * @param[in] n_option                Describes the option field that should be set with the value.
 * @param[in] value                   Single value setting the field selected by n_option.
 */
void kernel_chainstate_load_options_set(
    kernel_ChainstateLoadOptions* chainstate_load_options,
    kernel_ChainstateLoadOptionType n_option,
    bool value
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * Destroy the chainstate load options
 */
void kernel_chainstate_load_options_destroy(kernel_ChainstateLoadOptions* chainstate_load_options);

/**
 * @brief This function must be called to initialize the chainstate manager
 * before doing validation tasks or interacting with its indexes.
 *
 * @param[in] context                 Non-null.
 * @param[in] chainstate_load_options Non-null, created by kernel_chainstate_load_options_create.
 * @param[in] chainstate_manager      Non-null, will load the chainstate(s) and initialize indexes.
 * @return                            True on success, false on error.
 */
bool BITCOINKERNEL_WARN_UNUSED_RESULT kernel_chainstate_manager_load_chainstate(
    const kernel_Context* context,
    kernel_ChainstateLoadOptions* chainstate_load_options,
    kernel_ChainstateManager* chainstate_manager
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(2) BITCOINKERNEL_ARG_NONNULL(3);

/**
 * @brief May be called after kernel_chainstate_manager_load_chainstate to
 * initialize the chainstate manager. Triggers the start of a reindex if the
 * option was previously set for the chainstate and block manager. Can also
 * import an array of existing block files selected by the user.
 *
 * @param[in] context              Non-null.
 * @param[in] chainstate_manager   Non-null.
 * @param[in] block_file_paths     Nullable, array of block files described by their full filesystem paths.
 * @param[in] block_file_paths_len Length of the block_file_paths array.
 * @return                         True if the import blocks call was completed successfully.
 */
bool kernel_import_blocks(const kernel_Context* context,
                          kernel_ChainstateManager* chainstate_manager,
                          const char** block_file_paths, size_t block_file_paths_len
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(2);

/**
 * @brief Process and validate the passed in block with the chainstate manager.
 * If processing failed, some information can be retrieved through the status
 * enumeration.
 *
 * @param[in] context            Non-null.
 * @param[in] chainstate_manager Non-null.
 * @param[in] block              Non-null, block to be validated.
 * @param[out] status            Nullable, will contain an error/success code for the operation.
 * @return                       True if processing the block was successful.
 */
bool BITCOINKERNEL_WARN_UNUSED_RESULT kernel_chainstate_manager_process_block(
    const kernel_Context* context,
    kernel_ChainstateManager* chainstate_manager,
    kernel_Block* block,
    kernel_ProcessBlockStatus* status
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(2) BITCOINKERNEL_ARG_NONNULL(3);

/**
 * @brief Parse a serialized raw block into a new block object.
 *
 * @param[in] raw_block     Non-null, serialized block.
 * @param[in] raw_block_len Length of the serialized block.
 * @return                  The allocated block, or null on error.
 */
kernel_Block* BITCOINKERNEL_WARN_UNUSED_RESULT kernel_block_create(
    const unsigned char* raw_block, size_t raw_block_len
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * Destroy the block.
 */
void kernel_block_destroy(kernel_Block* block);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // BITCOIN_KERNEL_BITCOINKERNEL_H