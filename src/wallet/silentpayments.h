#ifndef BITCOIN_WALLET_SILENTPAYMENTS_H
#define BITCOIN_WALLET_SILENTPAYMENTS_H

#include <addresstype.h>
#include <coins.h>
#include <key_io.h>
#include <pubkey.h>
#include <undo.h>
#include <util/hasher.h>
#include <util/result.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/types.h>
#include <unordered_map>

namespace wallet {

/**
 * @brief Compute the ECDH public key for the shared secret.
 *
 * @param seckey      The private key. This private key is either the receiver's scan key or the
 *                    sum of the sender's input private keys (excluding inputs not eligible for
 *                    shared secret derivation).
 * @param pubkey      The public key. This public key is either the receiver's scan public key or the
 *                    sum of the sender's input public keys (excluding inputs not eligible for
 *                    shared secret derivation).
 * @param inputs_hash The tagged hash of hash of the smallest outpoint and sum of the eligible
 *                    input public keys.
 * @return CPubKey    The ECDH public key. This ECDH result is unhashed and should not be used
 *                    outside of silent payments.
 */
CPubKey ComputeECDH(const CKey& seckey, const CPubKey& pubkey, const uint256& inputs_hash);

/**
 * @brief Compute the tagged hash of the smallest outpoint and the sum of the eligible input public keys.
 *
 * The "Inputs Hash" is used as a nonce to prevent the same outputs being generated when a sender
 * is reusing the same inputs in multiple payments to the same recipient. The smallest outpoint
 * works as a deterministic nonce because an outpoint uniquely identifies a UTXO and thus is unique
 * for each transaction.
 *
 * @param tx_outpoints      The transaction outpoints.
 * @param sum_input_pubkeys The sum of the eligible input public keys.
 * @return uint256          The computed hash value.
 *
 * @see ComputeInputsHash(const std::vector<COutPoint>& tx_outpoints, const CPubKey& sum_input_pubkeys);
 */
uint256 ComputeInputsHash(const std::vector<COutPoint>& tx_outpoints, const CPubKey& sum_input_pubkeys);

/**
 * @brief Compute the shared secret tweak.
 *
 * In a single transaction, a sender can create multiple outputs for the same recipient. To prevent
 * needing to do an ECDH for each output, the ECDH public key is calculated once for the transaction
 * and then hashed with the counter k. The outputs must be created sequentially starting with `k=0`.
 *
 * @param ecdh_pubkey The ECDH public key.
 * @param k The output counter.
 * @return uint256 The shared secret tweak for output_k.
 */
uint256 ComputeSharedSecretTweak(const CPubKey& ecdh_pubkey, const uint32_t k);

/**
 * @brief Compute the silent payment label tweak.
 *
 * The receiving wallet may hand out labeled silent payment addresses to determine the origin of a payment.
 * Labels are specified by hashing the receivers scan key with a counter m. `m=0` is reserved for generating
 * change outputs for the receiver. Additional labels can be specified starting from `m=1`. The counter m
 * is hashed with the secret scan key to prevent an external observer from learning anything about the
 * receiver's labels.
 *
 * It is strongly recommended labels be created sequentially starting from `m=1`. Doing so ensures that
 * label data is not critical for backups, as the receiving wallet can pregenerate labels starting from 1
 * up to some sufficiently large M when recovering from a backup.
 *
 * @param scan_key The secret scan key.
 * @param m Integer representing the "m-th" label. m=0 is reserved for the change output.
 * @return uint256 The computed silent payment label tweak.
 */
uint256 ComputeSilentPaymentLabelTweak(const CKey& scan_key, const int m);

/**
 * @brief Generate a silent payment labeled address.
 *
 * @param receiver The receiver's silent payment destination (i.e. scan and spend public keys).
 * @param label The label tweak
 * @return V0SilentPaymentDestination The slient payment destination, with `B_spend -> B_spend + label * G`.
 *
 * @see ComputeSilentPaymentLabelTweak(const CKey& scan_key, const int m);
 */
V0SilentPaymentDestination GenerateSilentPaymentLabeledAddress(const V0SilentPaymentDestination& receiver, const uint256& label);

/**
 * @brief Generate silent payment taproot destinations.
 *
 * Given a set of silent payment destinations, generate the requested number of outputs. If a silent payment
 * destination is repeated, this indicates multiple outputs are requested for the same recipient. The silent payment
 * desintaions are passed in map where the key indicates their desired position in the final tx.vout array.
 *
 * @param seckey      The private key. This private key is either the receiver's scan key or the
 *                    sum of the sender's input private keys (excluding inputs not eligible for
 *                    shared secret derivation).
 * @param inputs_hash The tagged hash of hash of the smallest outpoint and sum of the eligible
 *                    input public keys.
 * @param sp_dests    The silent payment destinations.
 * @return std::map<size_t, WitnessV1Taproot> The generated silent payment taproot destinations.
 *
 * @see ComputeInputsHash(const std::vector<COutPoint>& tx_outpoints, const CPubKey& sum_input_pubkeys);
 */
std::map<size_t, WitnessV1Taproot> GenerateSilentPaymentTaprootDestinations(const CKey& seckey, const uint256& inputs_hash, const std::map<size_t, V0SilentPaymentDestination>& sp_dests);

/**
 * @brief Get silent payment tweak data from transaction inputs.
 *
 * Get the necessary data from the transaction inputs to be able to scan the transaction outputs for silent payment outputs.
 * This requires knowledge of the prevout scriptPubKey, which is passed via `coins`.
 *
 * If the transaction has silent payment eligible inputs, the public keys from these inputs are returned as a sum along with
 * the transaction input hash. If there are no eligible inputs, nullopt is returned, indicating that this transaction does not
 * contain silent payment outputs.
 *
 * @param vin                                         The transaction inputs.
 * @param coins                                       The coins (potentially) spent in this transaction.
 * @return std::optional<std::pair<uint256, CPubKey>> The silent payment tweak data, or nullopt if not found.
 */
std::optional<std::pair<uint256, CPubKey>> GetSilentPaymentTweakDataFromTxInputs(const std::vector<CTxIn>& vin, const std::map<COutPoint, Coin>& coins);

/**
 * @brief Get the public key from an input.
 *
 * Get the public key from a silent payment eligible input. This requires knowlegde of the prevout
 * scriptPubKey to determine the type of input and whether or not it is eligible for silent payments.
 *
 * If the input is not eligible for silent payments, the input is skipped (indicated by returning a nullopt).
 *
 * @param txin                    The transaction input.
 * @param spk                     The scriptPubKey of the prevout.
 * @return std::optional<CPubKey> The public key, or nullopt if not found.
 */
std::optional<CPubKey> GetPubKeyFromInput(const CTxIn& txin, const CScript& spk);

/**
 * @brief Get the silent payment output tweaks from a transaction.
 *
 * Scan the transaction for silent payment outputs intendended for us. The shared secret tweak is returned
 * for each output found. This tweak data is needed to spend the output, by adding it to the spend secret key.
 * If no tweak data is returned, this transaction does not contain silent payment outputs intended for us.
 *
 * While labels are optional for the receiver, it is strongly recommended that the change label is always checked
 * when scanning.
 *
 * @param spend_pubkey          The receiver's spend public key.
 * @param ecdh_pubkey           The ECDH public key.
 * @param output_pub_keys       The taproot output public keys.
 * @param labels                The receiver's labels.
 * @return std::vector<uint256> The transaction output tweaks.
 *
 * @see ComputeSilentPaymentLabelTweak(const CKey& scan_key, const int m);
 * @see ComputeECDH(const CKey& seckey, const CPubKey& pubkey, const uint256& inputs_hash);
 */
std::optional<std::vector<uint256>> GetTxOutputTweaks(const CPubKey& spend_pubkey, const CPubKey& ecdh_pubkey, std::vector<XOnlyPubKey> output_pub_keys, const std::map<CPubKey, uint256>& labels);

/**
 * @brief Sum the input private keys.
 *
 * Sum the input private keys, making sure to negate the taproot private keys if necessary. Taproot outputs
 * always use the even Y coordinate, so its essential to use the correct taproot private key (the private key
 * corresponding to the even Y coordinate) in the private key sum.
 *
 * @param sender_secret_keys The sender's silent payment eligible secret keys.
 * @return CKey              The sum of the input private keys.
 */
CKey SumInputPrivKeys(const std::vector<std::pair<CKey, bool>>& sender_secret_keys);

/**
 * @brief Sum the input public keys.
 *
 * @param input_pubkeys The silent payments eligible input public keys.
 * @return CPubKey The sum of the input public keys.
 */
CPubKey SumInputPubKeys(const std::vector<CPubKey>& input_pubkeys);

/**
 * SilentPaymentsSPKM: implemented similar to the legacy SPKMan due to silent payments not really
 * conceptually meeting the descriptors requirement. This is because each silent payment is independent
 * and only related to the transaction it is in. This is different than the descriptors model where each
 * output is derived from some master key with instructions on which type of script template to generate.
 *
 * It may make sense to use a descriptor based SPKMan, if only for the wallet compatibility benefits of
 * the descriptor DSL, but this is left for future work and the current implementation works for testing
 * send and receive.
 */
class SilentPaymentsSPKM : public ScriptPubKeyMan
{
private:
    //! Destination containing scan and spend pubkeys
    V0SilentPaymentDestination m_address GUARDED_BY(cs_sp_man);
    //! Change destination (not stored, generated deterministically)
    V0SilentPaymentDestination m_change_address GUARDED_BY(cs_sp_man);

    //! The scan private key itself. Must not be encrypted.
    CKey m_scan_key GUARDED_BY(cs_sp_man);

    //! The unencrypted spend private key, if wallet is not encrypted
    CKey m_spend_key GUARDED_BY(cs_sp_man);
    //! The encrypted spend private key, if wallet is encrypted
    std::vector<unsigned char> m_spend_crypted_key GUARDED_BY(cs_sp_man);

    //! Map of output script to final silent payments tweak for that script, including the label
    //! The tweak is the sha256(ecdh_shared_secret || output_counter) + label
    std::unordered_map<CScript, uint256, SaltedSipHasher> m_spk_tweaks GUARDED_BY(cs_sp_man);

    //! Map of label index to the corresponding curve point as a Pubkey
    std::map<CPubKey, uint256> m_sp_labels GUARDED_BY(cs_sp_man);

    //! Timestamp for this spkm's creation
    int64_t m_creation_time;

    //! Number of labels that have been requested (highest label index + 1)
    int64_t m_labels_used;

    //! 256-bit ID
    uint256 m_id;

    //! Setup the labels map and the change label and its output
    void SetupLabels(int64_t labels_size) EXCLUSIVE_LOCKS_REQUIRED(cs_sp_man);

    //! Helper for getting SigningProviders with and without private keys
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(const CScript& script, bool include_private) const EXCLUSIVE_LOCKS_REQUIRED(cs_sp_man);

public:
    //! Construct a SilentPaymentsSPKM from stored data
    SilentPaymentsSPKM(WalletStorage& storage, const uint256& id, const V0SilentPaymentDestination& address, const CKey& scan_key, const CKey& spend_key, const std::vector<unsigned char>& spend_ckey, const std::vector<uint256>& tweaks, int64_t labels_size, int64_t creation_time, int64_t labels_used);
    //! Construct a new autogenerated SilentPaymentsSPKM
    SilentPaymentsSPKM(WalletStorage& storage, int64_t labels_size, const CExtKey& master_key);

    mutable RecursiveMutex cs_sp_man;

    util::Result<CTxDestination> GetNewDestination(const OutputType type) override;
    isminetype IsMine(const CScript& script) const override;

    bool CheckDecryptionKey(const CKeyingMaterial& master_key, bool accept_no_keys = false) override;
    bool Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch) override;

    util::Result<CTxDestination> GetReservedDestination(const OutputType type, bool internal, int64_t& index, CKeyPool& keypool) override;

    bool TopUp(unsigned int size = 0) override;

    // HD isn't really a concept that makes sense for silent payments, just return true unconditionally to avoid breaking other stuff
    bool IsHDEnabled() const override { return true; }
    bool CanGetAddresses(bool internal = false) const override { return true; }
    bool HavePrivateKeys() const override
    {
        // TODO: Watch-only silent payments are not yet implemented
        return true;
    }

    std::optional<int64_t> GetOldestKeyPoolTime() const override;
    unsigned int GetKeyPoolSize() const override;
    int64_t GetTimeFirstKey() const override;

    std::unique_ptr<CKeyMetadata> GetMetadata(const CTxDestination& dest) const override;
    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const override;

    bool CanProvide(const CScript& script, SignatureData& sigdata) override;
    bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const override;
    SigningResult SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const override;
    TransactionError FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, int sighash_type = SIGHASH_DEFAULT, bool sign = true, bool bip32derivs = false, int* n_signed = nullptr, bool finalize = true) const override;

    uint256 GetID() const override;

    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const override;

    isminetype IsMineSilentPayments(const CTransaction& tx, const std::map<COutPoint, Coin>& coins);
    bool AddTweakWithDB(WalletBatch& batch, const uint256& tweak) EXCLUSIVE_LOCKS_REQUIRED(cs_sp_man);
};
} // namespace wallet
#endif // BITCOIN_WALLET_SILENTPAYMENTS_H
